// SPDX-FileCopyrightText: 2026 Andrzej Piotrowski
// SPDX-License-Identifier: Apache-2.0

/**
 * Cloudflare Worker: sbom-explorer-upload
 *
 * Accepts SBOM Explorer submissions from the static site,
 * validates them, and creates a GitHub PR for owner review.
 *
 * Endpoints:
 *   POST /api/upload       — accept a submission, file a PR
 *   POST /api/submissions  — alias of /api/upload (sbom-explorer-submission/1 envelope)
 *   GET  /api/health       — health check
 */

const GITHUB_API = "https://api.github.com";
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024; // 5 MB
const ENVELOPE_SCHEMA = "sbom-explorer-submission/1";
// ids end up in a git ref and a file path -> strict charset
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
const VERSION_RE = /^v?[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/;
// products whose SBOMs are signed/archived and must not be touched via upload
const PROTECTED_IDS = ["raidio-bot", "raidio.bot"];
const ALLOWED_ORIGINS = [
  "https://andrzej-piotrowski-pl.github.io",
  "https://andrzej-piotrowski-pl.github.io/sbomnix",
];

// ---------------------------------------------------------------------------
// CORS helper
// ---------------------------------------------------------------------------
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : "*";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

// ---------------------------------------------------------------------------
// Basic validation
// ---------------------------------------------------------------------------
function validateSubmission(body) {
  const errors = [];
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    errors.push("body must be a JSON object");
    return errors;
  }
  const isEnvelope = body.schema !== undefined;
  if (isEnvelope && body.schema !== ENVELOPE_SCHEMA) {
    errors.push(`schema must be ${ENVELOPE_SCHEMA}`);
  }
  const product = body.product;
  if (!product || typeof product !== "object") {
    errors.push("product.id is required");
  } else {
    if (typeof product.id !== "string" || !ID_RE.test(product.id)) {
      errors.push("product.id is required and must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$");
    }
    // name is required for the old {product, sbom} shape, optional in the envelope
    if (!isEnvelope && !product.name) {
      errors.push("product.name is required");
    }
  }
  if (body.variant !== undefined) {
    const vid = body.variant && body.variant.id;
    if (typeof vid !== "string" || !ID_RE.test(vid)) {
      errors.push("variant.id must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$");
    }
  }
  if (body.version !== undefined && (typeof body.version !== "string" || !VERSION_RE.test(body.version))) {
    errors.push("version must match ^v?[A-Za-z0-9][A-Za-z0-9._-]{0,60}$");
  }
  if (!body.sbom || typeof body.sbom !== "object") {
    errors.push("sbom (CycloneDX JSON) is required");
  } else if (body.sbom.bomFormat !== "CycloneDX") {
    errors.push("sbom.bomFormat must be CycloneDX");
  }
  return errors;
}

// ---------------------------------------------------------------------------
// GitHub PR creation
// ---------------------------------------------------------------------------
async function createPR(token, productId, submission, timestamp, vexIgnored = false) {
  const branch = `submission/${productId}/${timestamp}`;
  const path = `submissions/${productId}/${timestamp}.json`;
  const content = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(submission, null, 2))));

  // 1. Get default branch
  const repo = "andrzej-piotrowski-pl/sbomnix";
  const repoInfo = await fetch(`${GITHUB_API}/repos/${repo}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
  });
  if (!repoInfo.ok) throw new Error(`GitHub repo fetch failed: ${repoInfo.status}`);
  const repoData = await repoInfo.json();
  const defaultBranch = repoData.default_branch;

  // 2. Get current tree to find the docs/ sha
  const ref = await fetch(`${GITHUB_API}/repos/${repo}/git/ref/heads/${defaultBranch}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
  });
  if (!ref.ok) throw new Error(`GitHub ref fetch failed: ${ref.status}`);
  const refData = await ref.json();
  const baseSha = refData.object.sha;

  const tree = await fetch(`${GITHUB_API}/repos/${repo}/git/trees/${baseSha}?recursive=1`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
  });
  if (!tree.ok) throw new Error(`GitHub tree fetch failed: ${tree.status}`);
  const treeData = await tree.json();

  // Find docs/data/manifest.json sha for the new tree
  const manifestEntry = treeData.tree.find(e => e.path === "docs/data/manifest.json");
  const manifestSha = manifestEntry ? manifestEntry.sha : null;

  // 3. Create blob for new submission file
  const blobResp = await fetch(`${GITHUB_API}/repos/${repo}/git/blobs`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    body: JSON.stringify({ content, encoding: "base64" }),
  });
  if (!blobResp.ok) throw new Error(`GitHub blob creation failed: ${blobResp.status}`);
  const blobData = await blobResp.json();
  const fileSha = blobData.sha;

  // 4. Build new tree (append submission file)
  const newTree = [...treeData.tree, {
    path,
    mode: "100644",
    type: "blob",
    sha: fileSha,
  }];

  const newTreeResp = await fetch(`${GITHUB_API}/repos/${repo}/git/trees`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    body: JSON.stringify({ tree: newTree, base_tree: baseSha }),
  });
  if (!newTreeResp.ok) throw new Error(`GitHub tree creation failed: ${newTreeResp.status}`);
  const newTreeData = await newTreeResp.json();

  // 5. Create commit
  const commitResp = await fetch(`${GITHUB_API}/repos/${repo}/git/commits`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    body: JSON.stringify({
      message: `Submission: ${productId} — new SBOM upload`,
      tree: newTreeData.sha,
      parents: [baseSha],
    }),
  });
  if (!commitResp.ok) throw new Error(`GitHub commit failed: ${commitResp.status}`);
  const commitData = await commitResp.json();

  // 6. Create branch
  await fetch(`${GITHUB_API}/repos/${repo}/git/refs`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: commitData.sha }),
  });

  // 7. Open PR
  const prResp = await fetch(`${GITHUB_API}/repos/${repo}/pulls`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    body: JSON.stringify({
      title: `Submission: ${productId} — new SBOM upload`,
      head: branch,
      base: defaultBranch,
      body: `Automated submission from SBOM Explorer.\n\nProduct: **${productId}**\nTimestamp: ${timestamp}\n\n${vexIgnored ? "Note: a `vex` section was supplied but ignored (VEX decisions come from the product owner only).\n\n" : ""}Review and merge to publish.`,
      draft: true,
    }),
  });
  if (!prResp.ok) throw new Error(`GitHub PR creation failed: ${prResp.status}`);
  const prData = await prResp.json();

  return { prUrl: prData.html_url, prNumber: prData.number, branch };
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { ...corsHeaders(request), "Access-Control-Max-Age": "86400" } });
    }

    // Health check
    if (url.pathname === "/api/health") {
      return new Response(JSON.stringify({
        status: "ok",
        uptime: Date.now(),
        mode: "pr",
        upload_needs_token: false,
        max_bytes: MAX_UPLOAD_SIZE,
      }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders(request) },
      });
    }

    // Upload endpoint (/api/submissions is an alias)
    if ((url.pathname === "/api/upload" || url.pathname === "/api/submissions") && request.method === "POST") {
      const cors = corsHeaders(request);

      // Size check
      const contentLength = parseInt(request.headers.get("Content-Length") || "0", 10);
      if (contentLength > MAX_UPLOAD_SIZE) {
        return new Response(JSON.stringify({ error: "payload too large (max 5 MB)" }), {
          status: 413,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Parse body (re-check real size: Content-Length may be absent or wrong)
      let body;
      try {
        const raw = await request.text();
        if (new TextEncoder().encode(raw).length > MAX_UPLOAD_SIZE) {
          return new Response(JSON.stringify({ error: "payload too large (max 5 MB)" }), {
            status: 413,
            headers: { "Content-Type": "application/json", ...cors },
          });
        }
        body = JSON.parse(raw);
      } catch {
        return new Response(JSON.stringify({ error: "invalid JSON" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Validate
      const errors = validateSubmission(body);
      if (errors.length) {
        return new Response(JSON.stringify({ error: "validation failed", details: errors }), {
          status: 422,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Protected products (signed/archived releases) cannot be modified
      if (PROTECTED_IDS.includes(body.product.id.toLowerCase())) {
        return new Response(JSON.stringify({ error: "product is protected and cannot be modified via upload" }), {
          status: 403,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Check for GitHub token
      const token = env.GITHUB_TOKEN;
      if (!token) {
        return new Response(JSON.stringify({ error: "server misconfigured — no upload backend" }), {
          status: 503,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }

      // Create PR
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-").replace("T", "-").slice(0, 19);
      const productId = body.product.id;
      // VEX decisions come from the product owner only: drop, never forward
      const { vex, ...submission } = body;
      const vexIgnored = vex !== undefined;

      try {
        const result = await createPR(token, productId, submission, timestamp, vexIgnored);
        return new Response(JSON.stringify({
          ok: true,
          message: "Submission received — a draft PR has been created for review.",
          pr_url: result.prUrl,
          pr_number: result.prNumber,
          branch: result.branch,
          ...(vexIgnored ? { vex_ignored: true } : {}),
        }), {
          status: 201,
          headers: { "Content-Type": "application/json", ...cors },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "failed to create PR", detail: err.message }), {
          status: 502,
          headers: { "Content-Type": "application/json", ...cors },
        });
      }
    }

    // Unknown endpoint
    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...corsHeaders(request) },
    });
  },
};
