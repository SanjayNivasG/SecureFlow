import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  scanPullRequest: vi.fn(),
  checksCreate: vi.fn(),
  createComment: vi.fn(),
  updateScanJobProgress: vi.fn(),
  explain: vi.fn(),
  getContent: vi.fn(),
  pullsGet: vi.fn(),
  fetchPullRequestFiles: vi.fn(),
}));

vi.mock("@/lib/armor/scanner", () => ({
  scanner: { scanPullRequest: mocks.scanPullRequest },
  parseSecureFlowIgnore: (content: string) => ({
    ignoredPaths: content
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    placeholders: [],
  }),
}));
vi.mock("@/lib/armor/iq", () => ({
  iq: {
    evaluateFindings: (findings: Array<{ severity: string }>) =>
      findings.some((f) => f.severity === "CRITICAL") ? "BLOCKED" : "PASS",
  },
}));
vi.mock("@/ai/flows/developer-receives-ai-security-explanations", () => ({
  developerReceivesAISecurityExplanations: mocks.explain,
}));
vi.mock("@/lib/queue/worker", () => ({
  getGitHubAppCredentials: () => ({ appId: "1", privateKey: "key" }),
}));
vi.mock("@/lib/queue/scanQueue", () => ({
  updateScanJobProgress: mocks.updateScanJobProgress,
}));
vi.mock("@/lib/prisma", () => ({
  default: { findingTriage: { findMany: vi.fn().mockResolvedValue([]) } },
}));
vi.mock("@/lib/github/pull-request-files", () => ({
  fetchPullRequestFiles: mocks.fetchPullRequestFiles,
}));
vi.mock("octokit", () => ({
  App: class {
    async getInstallationOctokit() {
      return {
        rest: {
          checks: { create: mocks.checksCreate },
          issues: { createComment: mocks.createComment },
          repos: { getContent: mocks.getContent },
          pulls: { get: mocks.pullsGet },
        },
      };
    }
  },
}));

import { processScanJob, ScanIncompleteError } from "./scanEngine";
import type { ScanJobData } from "@/lib/queue/scanQueue";

/** Twelve files, so the engine scans them in two chunks (10 + 2). */
const fileChanges = Array.from({ length: 12 }, (_, i) => ({
  filename: `src/file-${i}.ts`,
  patch: `+const value${i} = ${i};`,
}));

const jobData = {
  scanJobId: "job-1",
  repositoryId: "",
  installationId: 42,
  repositoryFullName: "acme/api",
  prNumber: 7,
  headSha: "abc123",
  fileChanges,
  activePolicies: [],
  customIgnores: [],
  customPlaceholders: [],
} as unknown as ScanJobData;

/** Job data with empty fileChanges — the shape that POST /api/findings produces (#3). */
const apiJobData: ScanJobData = {
  ...jobData,
  fileChanges: [],
};

describe("processScanJob chunk failures", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.updateScanJobProgress.mockResolvedValue(undefined);
    mocks.explain.mockResolvedValue({
      explanation: "e",
      remediationSuggestions: "r",
      promptInjectionSuspected: false,
    });
    // Default: GitHub returns two files for the pull request.
    mocks.fetchPullRequestFiles.mockResolvedValue({
      files: [
        { filename: "src/real.ts", patch: "+const real = true;", status: "modified" },
        { filename: "src/another.ts", patch: "+const x = 1;", status: "added" },
      ],
      fetched: 2,
      truncated: false,
      totalChanged: 2,
    });
  });

  it("fails the scan instead of reporting PASS when the analysis engine is unavailable", async () => {
    mocks.scanPullRequest.mockRejectedValue(
      new Error("ScanFailedAnalysisEngineUnavailable: LLM scan failed after all retries."),
    );

    const run = processScanJob(jobData);

    await expect(run).rejects.toBeInstanceOf(ScanIncompleteError);
    await expect(run).rejects.toThrow(/10 file\(s\) could not be analysed/);
    expect(mocks.checksCreate).not.toHaveBeenCalled();
  });

  it("fails the scan when a later chunk fails, even though an earlier one succeeded", async () => {
    mocks.scanPullRequest.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error("429"));

    const error = await processScanJob(jobData, undefined, { report: false, persist: false }).catch(
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(ScanIncompleteError);
    expect((error as ScanIncompleteError).failedFiles).toEqual([
      "src/file-10.ts",
      "src/file-11.ts",
    ]);
  });

  it("still completes and reports when every chunk scans", async () => {
    mocks.scanPullRequest.mockResolvedValue([]);

    const result = await processScanJob(jobData);

    expect(mocks.scanPullRequest).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ scannedFiles: 12, vulnerabilitiesFound: 0, verdict: "PASS" });
    expect(mocks.checksCreate).toHaveBeenCalledWith(
      expect.objectContaining({ conclusion: "success", head_sha: "abc123" }),
    );
  });

  describe("ignore configuration", () => {
    const quiet = { report: false, persist: false, enrich: false };
    const base64 = (text: string) => Buffer.from(text).toString("base64");
    const notFound = () => Object.assign(new Error("Not Found"), { status: 404 });
    const scanCall = () => mocks.scanPullRequest.mock.calls[0];
    const expectScannedWith = (ignores: string[], placeholders: string[] = []) =>
      expect(scanCall()).toEqual([expect.any(Array), expect.any(Array), ignores, placeholders]);

    beforeEach(() => {
      mocks.getContent.mockReset();
      mocks.pullsGet.mockReset();
      mocks.scanPullRequest.mockResolvedValue([]);
      vi.spyOn(console, "warn").mockImplementation(() => {});
    });

    it("reads .secureflowignore from the base branch named in the job", async () => {
      mocks.getContent.mockResolvedValue({ data: { content: base64("docs/**\ntests/**") } });

      await processScanJob({ ...jobData, baseRef: "main" } as ScanJobData, undefined, quiet);

      expect(mocks.pullsGet).not.toHaveBeenCalled();
      expect(mocks.getContent).toHaveBeenCalledWith({
        owner: "acme",
        repo: "api",
        path: ".secureflowignore",
        ref: "main",
      });
      expectScannedWith(["docs/**", "tests/**"]);
    });

    it("looks the base branch up from the pull request when the job does not name one", async () => {
      mocks.pullsGet.mockResolvedValue({ data: { base: { ref: "develop" } } });
      mocks.getContent.mockResolvedValue({ data: { content: base64("docs/**") } });

      await processScanJob(jobData, undefined, quiet);

      expect(mocks.pullsGet).toHaveBeenCalledWith({ owner: "acme", repo: "api", pull_number: 7 });
      expect(mocks.getContent).toHaveBeenCalledWith(expect.objectContaining({ ref: "develop" }));
      expectScannedWith(["docs/**"]);
    });

    it("is not switched off by a .secureflowignore the pull request adds on its own branch", async () => {
      // Nothing on the base branch; the head commit (`abc123`) adds a file that
      // ignores everything. Only a read at the head would ever see it.
      mocks.getContent.mockImplementation(async ({ ref }: { ref: string }) => {
        if (ref === "main") throw notFound();
        return { data: { content: base64("**\n[placeholders]\nAKIA") } };
      });

      await processScanJob({ ...jobData, baseRef: "main" } as ScanJobData, undefined, quiet);

      expectScannedWith([]);
      for (const [params] of mocks.getContent.mock.calls) {
        expect(params.ref).not.toBe("abc123");
      }
    });

    it("keeps server-supplied ignores in addition to the repository's own", async () => {
      mocks.getContent.mockResolvedValue({ data: { content: base64("docs/**") } });

      await processScanJob(
        { ...jobData, baseRef: "main", customIgnores: ["vendor/**"] } as ScanJobData,
        undefined,
        quiet,
      );

      expectScannedWith(["vendor/**", "docs/**"]);
    });

    it("scans without ignore rules when no base branch can be determined", async () => {
      mocks.pullsGet.mockRejectedValue(new Error("GitHub is down"));

      await processScanJob(jobData, undefined, quiet);

      expect(mocks.getContent).not.toHaveBeenCalled();
      expectScannedWith([]);
    });
  });
});

describe("processScanJob — scan-input integrity (#3)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.updateScanJobProgress.mockResolvedValue(undefined);
    mocks.explain.mockResolvedValue({
      explanation: "e",
      remediationSuggestions: "r",
      promptInjectionSuspected: false,
    });
    mocks.fetchPullRequestFiles.mockResolvedValue({
      files: [
        { filename: "src/real.ts", patch: "+const real = true;", status: "modified" },
        { filename: "src/another.ts", patch: "+const x = 1;", status: "added" },
      ],
      fetched: 2,
      truncated: false,
      totalChanged: 2,
    });
    mocks.scanPullRequest.mockResolvedValue([]);
  });

  it("fetches authoritative PR files from GitHub when fileChanges is empty (API path)", async () => {
    // This is the shape POST /api/findings always produces after the fix: the
    // schema no longer accepts fileChanges, so the queue payload carries [].
    await processScanJob(apiJobData, undefined, { report: false, persist: false, enrich: false });

    expect(mocks.fetchPullRequestFiles).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ owner: "acme", repo: "api", pullNumber: 7 }),
    );
  });

  it("scans the GitHub-provided files, not any caller-supplied list (#3)", async () => {
    // If a caller had supplied fileChanges: [{ filename: "fake.ts", patch: "+safe" }]
    // the engine must NOT scan that \u2014 it must scan what GitHub says changed.
    await processScanJob(apiJobData, undefined, { report: false, persist: false, enrich: false });

    // The scanner received the real GitHub files, not a caller-supplied list.
    expect(mocks.scanPullRequest).toHaveBeenCalledWith(
      [
        { filename: "src/real.ts", patch: "+const real = true;" },
        { filename: "src/another.ts", patch: "+const x = 1;" },
      ],
      expect.any(Array),
      expect.any(Array),
      expect.any(Array),
    );
  });

  it("headSha is forwarded to the GitHub fetch so the correct commit is validated", async () => {
    await processScanJob(apiJobData, undefined, { report: false, persist: false, enrich: false });

    // The headSha is used for .secureflowignore resolution; the PR file fetch
    // is scoped to the pull request number, not the SHA, which is GitHub's API
    // contract. Confirm both calls receive the right identifiers.
    expect(mocks.fetchPullRequestFiles).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ pullNumber: apiJobData.prNumber }),
    );
  });

  it("webhook-path job (non-empty fileChanges) uses its own list and does not call fetchPullRequestFiles", async () => {
    // The webhook worker fetches files from GitHub itself (HMAC-verified webhook),
    // then passes them in fileChanges. The engine must not fetch again.
    const webhookData: ScanJobData = {
      ...apiJobData,
      fileChanges: [{ filename: "src/webhook-real.ts", patch: "+const wh = 1;" }],
    };

    await processScanJob(webhookData, undefined, { report: false, persist: false, enrich: false });

    expect(mocks.fetchPullRequestFiles).not.toHaveBeenCalled();
    expect(mocks.scanPullRequest).toHaveBeenCalledWith(
      [{ filename: "src/webhook-real.ts", patch: "+const wh = 1;" }],
      expect.any(Array),
      expect.any(Array),
      expect.any(Array),
    );
  });
});
