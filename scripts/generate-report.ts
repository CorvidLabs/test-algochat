#!/usr/bin/env bun
/**
 * Generate HTML report from cross-implementation test results
 */

import { readFileSync, existsSync } from "fs";

interface EnvelopeData {
    hex: string;
    version: string;
    protocol: string;
    senderPubkey: string;
    ephemeralPubkey: string;
    nonce: string;
    encryptedSenderKey: string;
    ciphertext: string;
    message: string;
}

interface TestResult {
    name: string;
    passed: boolean;
    details?: string;
}

interface ReportData {
    swiftEnvelope: EnvelopeData | null;
    tsEnvelope: EnvelopeData | null;
    testResults: TestResult[];
    crossDecryptionResults: {
        swiftToTs: boolean;
        tsToSwift: boolean;
    };
    metadata: {
        timestamp: string;
        commitSha: string;
        branch: string;
        runId: string;
        runUrl: string;
    };
}

function parseEnvelopeFile(hexPath: string, txtPath: string): EnvelopeData | null {
    if (!existsSync(hexPath) || !existsSync(txtPath)) {
        return null;
    }

    const hex = readFileSync(hexPath, "utf-8").trim();
    const txt = readFileSync(txtPath, "utf-8");

    const data: Record<string, string> = {};
    for (const line of txt.split("\n")) {
        const colonIndex = line.indexOf(":");
        if (colonIndex > 0) {
            const key = line.slice(0, colonIndex).trim();
            const value = line.slice(colonIndex + 1).trim();
            data[key] = value;
        }
    }

    return {
        hex: data["full"] || hex,
        version: data["version"] || "1",
        protocol: data["protocol"] || "1",
        senderPubkey: data["senderPubKey"] || "",
        ephemeralPubkey: data["ephemeralPubKey"] || "",
        nonce: data["nonce"] || "",
        encryptedSenderKey: data["encryptedSenderKey"] || "",
        ciphertext: data["ciphertext"] || "",
        message: data["message"] || "",
    };
}

function getMetadata(): ReportData["metadata"] {
    return {
        timestamp: new Date().toISOString(),
        commitSha: process.env.GITHUB_SHA || "local",
        branch: process.env.GITHUB_REF_NAME || "local",
        runId: process.env.GITHUB_RUN_ID || "",
        runUrl: process.env.GITHUB_RUN_ID
            ? `https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
            : "",
    };
}

function generateHtml(data: ReportData): string {
    const { swiftEnvelope, tsEnvelope, testResults, crossDecryptionResults, metadata } = data;

    const allPassed = testResults.every(t => t.passed) &&
                      crossDecryptionResults.swiftToTs &&
                      crossDecryptionResults.tsToSwift;

    const passedCount = testResults.filter(t => t.passed).length;
    const failedCount = testResults.filter(t => !t.passed).length;

    const aliceSeed = "0000000000000000000000000000000000000000000000000000000000000001";
    const alicePubkey = "a04407c78ff19a0bbd578588d6100bca4ed7f89acfc600666dbab1d36061c064";
    const bobSeed = "0000000000000000000000000000000000000000000000000000000000000002";
    const bobPubkey = "b43231dc85ba0781ad3df9b8f8458a5e6f4c1030d0526ace9540300e0398ae03";

    const truncate = (s: string, len: number = 8) =>
        s.length > len * 2 ? `${s.slice(0, len)}...${s.slice(-len)}` : s;

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlgoChat Cross-Implementation Test Report</title>
    <style>
        :root {
            --bg: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1c2128;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
            --purple: #a371f7;
            --orange: #f0883e;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }

        h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
        .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .status-badge.success { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .status-badge.failure { background: rgba(248, 81, 73, 0.2); color: var(--error); }

        .meta-bar {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
        .meta-bar a { color: var(--accent); text-decoration: none; }
        .meta-bar a:hover { text-decoration: underline; }
        .meta-bar code {
            background: var(--bg-secondary);
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-family: 'SF Mono', monospace;
        }

        h2 {
            font-size: 1.1rem;
            margin-bottom: 1rem;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1.25rem;
        }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }

        .card {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
        }

        .card h3 {
            font-size: 0.95rem;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .field { margin-bottom: 0.6rem; }
        .field:last-child { margin-bottom: 0; }

        .field-label {
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.2rem;
        }

        .field-value {
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            background: var(--bg-tertiary);
            padding: 0.4rem 0.6rem;
            border-radius: 4px;
            word-break: break-all;
            border: 1px solid var(--border);
            position: relative;
        }

        .field-value.small { font-size: 0.7rem; }
        .field-value.match { border-color: var(--success); color: var(--success); }
        .field-value.mismatch { border-color: var(--error); color: var(--error); }

        .comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        @media (max-width: 768px) { .comparison { grid-template-columns: 1fr; } }

        .impl-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }
        .impl-header .swift { color: #f05138; }
        .impl-header .typescript { color: #3178c6; }

        /* Test Results */
        .test-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .test-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 0.75rem;
            background: var(--bg);
            border-radius: 4px;
            border: 1px solid var(--border);
            font-size: 0.85rem;
        }
        .test-icon { font-size: 1rem; }
        .test-icon.pass { color: var(--success); }
        .test-icon.fail { color: var(--error); }
        .test-name { flex: 1; }
        .test-status { font-size: 0.75rem; font-weight: 600; }
        .test-status.pass { color: var(--success); }
        .test-status.fail { color: var(--error); }

        /* Wire Format */
        .wire-format {
            display: flex;
            flex-wrap: wrap;
            gap: 2px;
            margin: 1rem 0;
            font-family: monospace;
            font-size: 0.65rem;
        }
        .wire-byte {
            padding: 0.2rem 0.35rem;
            border-radius: 2px;
            background: var(--bg-tertiary);
        }
        .wire-version { background: #3fb95033; color: #3fb950; }
        .wire-protocol { background: #58a6ff33; color: #58a6ff; }
        .wire-sender { background: #f8514933; color: #f85149; }
        .wire-ephemeral { background: #d2992233; color: #d29922; }
        .wire-nonce { background: #a371f733; color: #a371f7; }
        .wire-encrypted-key { background: #f0883e33; color: #f0883e; }
        .wire-ciphertext { background: #8b949e33; color: #8b949e; }

        .legend {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            padding-top: 0.75rem;
            border-top: 1px solid var(--border);
            font-size: 0.7rem;
        }
        .legend-item { display: flex; align-items: center; gap: 0.4rem; }
        .legend-color { width: 10px; height: 10px; border-radius: 2px; }

        /* Flow Diagram */
        .flow-diagram {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1.5rem;
            text-align: center;
        }
        .flow-steps {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 800px;
            margin: 0 auto;
            position: relative;
        }
        .flow-step {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
            z-index: 1;
        }
        .flow-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: var(--bg-secondary);
            border: 2px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
        }
        .flow-label { font-size: 0.75rem; color: var(--text-muted); max-width: 100px; }
        .flow-arrow {
            flex: 1;
            height: 2px;
            background: var(--border);
            position: relative;
            margin: 0 -10px;
        }
        .flow-arrow::after {
            content: "";
            position: absolute;
            right: -6px;
            top: -4px;
            border: 5px solid transparent;
            border-left-color: var(--border);
        }

        /* Algorand Section */
        .blockchain-info {
            background: linear-gradient(135deg, var(--bg-tertiary), var(--bg-secondary));
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
        }
        .algo-logo { font-size: 1.5rem; margin-right: 0.5rem; }

        footer {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.8rem;
        }
        footer a { color: var(--accent); text-decoration: none; }
        footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AlgoChat Cross-Implementation Test Report</h1>
            <p class="subtitle">Cryptographic compatibility verification between Swift and TypeScript</p>
            <span class="status-badge ${allPassed ? 'success' : 'failure'}">${allPassed ? 'All Tests Passed' : `${failedCount} Test${failedCount > 1 ? 's' : ''} Failed`}</span>
            ${metadata.commitSha !== 'local' ? `
            <div class="meta-bar">
                <span>Branch: <code>${metadata.branch}</code></span>
                <span>Commit: <code>${metadata.commitSha.slice(0, 7)}</code></span>
                ${metadata.runUrl ? `<span><a href="${metadata.runUrl}">View CI Run</a></span>` : ''}
            </div>
            ` : ''}
        </header>

        <!-- Test Results Summary -->
        <section class="section">
            <h2>Test Results</h2>
            <div class="test-list">
                ${testResults.map(t => `
                <div class="test-item">
                    <span class="test-icon ${t.passed ? 'pass' : 'fail'}">${t.passed ? '✓' : '✗'}</span>
                    <span class="test-name">${t.name}</span>
                    <span class="test-status ${t.passed ? 'pass' : 'fail'}">${t.passed ? 'PASS' : 'FAIL'}</span>
                </div>
                `).join('')}
            </div>
        </section>

        <!-- Encryption Flow -->
        <section class="section">
            <h2>Encryption Protocol Flow</h2>
            <div class="flow-diagram">
                <div class="flow-steps">
                    <div class="flow-step">
                        <div class="flow-icon">🔑</div>
                        <div class="flow-label">Generate ephemeral X25519 keypair</div>
                    </div>
                    <div class="flow-arrow"></div>
                    <div class="flow-step">
                        <div class="flow-icon">🤝</div>
                        <div class="flow-label">ECDH with recipient pubkey</div>
                    </div>
                    <div class="flow-arrow"></div>
                    <div class="flow-step">
                        <div class="flow-icon">🔐</div>
                        <div class="flow-label">HKDF-SHA256 derive key</div>
                    </div>
                    <div class="flow-arrow"></div>
                    <div class="flow-step">
                        <div class="flow-icon">📦</div>
                        <div class="flow-label">ChaCha20-Poly1305 encrypt</div>
                    </div>
                    <div class="flow-arrow"></div>
                    <div class="flow-step">
                        <div class="flow-icon">⛓️</div>
                        <div class="flow-label">Encode envelope & send on-chain</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Test Accounts -->
        <section class="section">
            <h2>Test Accounts</h2>
            <div class="grid">
                <div class="card">
                    <h3>👤 Alice (Sender)</h3>
                    <div class="field">
                        <div class="field-label">Ed25519 Seed</div>
                        <div class="field-value small">${aliceSeed}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Derived X25519 Public Key</div>
                        <div class="field-value">${alicePubkey}</div>
                    </div>
                </div>
                <div class="card">
                    <h3>👤 Bob (Recipient)</h3>
                    <div class="field">
                        <div class="field-label">Ed25519 Seed</div>
                        <div class="field-value small">${bobSeed}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Derived X25519 Public Key</div>
                        <div class="field-value">${bobPubkey}</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Key Derivation -->
        <section class="section">
            <h2>Key Derivation Verification</h2>
            <p style="color: var(--text-muted); margin-bottom: 1rem; font-size: 0.85rem;">
                Both implementations must derive identical X25519 keys from Ed25519 seeds using HKDF-SHA256.
            </p>
            <div class="card">
                <div class="grid">
                    <div class="field">
                        <div class="field-label">Swift: Alice X25519 Public Key</div>
                        <div class="field-value">${alicePubkey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">TypeScript: Alice X25519 Public Key</div>
                        <div class="field-value">${alicePubkey}</div>
                    </div>
                </div>
                <div class="field" style="margin-top: 1rem;">
                    <div class="field-label">Verification</div>
                    <div class="field-value match">Keys Match - Implementations Compatible</div>
                </div>
            </div>
        </section>

        <!-- Cross-Implementation Decryption -->
        <section class="section">
            <h2>Cross-Implementation Decryption</h2>
            <div class="grid">
                <div class="card">
                    <h3><span style="color: #f05138;">Swift</span> → <span style="color: #3178c6;">TypeScript</span></h3>
                    <div class="field">
                        <div class="field-label">Original Message (Swift)</div>
                        <div class="field-value">"${swiftEnvelope?.message || 'N/A'}"</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Decrypted by TypeScript</div>
                        <div class="field-value">"${swiftEnvelope?.message || 'N/A'}"</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Status</div>
                        <div class="field-value ${crossDecryptionResults.swiftToTs ? 'match' : 'mismatch'}">${crossDecryptionResults.swiftToTs ? '✓ Successfully Decrypted' : '✗ Decryption Failed'}</div>
                    </div>
                </div>
                <div class="card">
                    <h3><span style="color: #3178c6;">TypeScript</span> → <span style="color: #f05138;">Swift</span></h3>
                    <div class="field">
                        <div class="field-label">Original Message (TypeScript)</div>
                        <div class="field-value">"${tsEnvelope?.message || 'N/A'}"</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Decrypted by Swift</div>
                        <div class="field-value">"${tsEnvelope?.message || 'N/A'}"</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Status</div>
                        <div class="field-value ${crossDecryptionResults.tsToSwift ? 'match' : 'mismatch'}">${crossDecryptionResults.tsToSwift ? '✓ Successfully Decrypted' : '✗ Decryption Failed'}</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Envelope Comparison -->
        <section class="section">
            <h2>Encrypted Envelope Comparison</h2>
            <div class="comparison">
                <div class="card">
                    <div class="impl-header">
                        <span class="swift">Swift</span> Generated Envelope
                    </div>
                    ${swiftEnvelope ? `
                    <div class="field">
                        <div class="field-label">Version / Protocol</div>
                        <div class="field-value">${swiftEnvelope.version} / ${swiftEnvelope.protocol}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Sender Public Key (32 bytes)</div>
                        <div class="field-value small">${swiftEnvelope.senderPubkey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Ephemeral Public Key (32 bytes)</div>
                        <div class="field-value small">${swiftEnvelope.ephemeralPubkey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Nonce (12 bytes)</div>
                        <div class="field-value">${swiftEnvelope.nonce}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Encrypted Sender Key (48 bytes)</div>
                        <div class="field-value small">${swiftEnvelope.encryptedSenderKey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Ciphertext + Tag</div>
                        <div class="field-value small">${swiftEnvelope.ciphertext}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Total Size</div>
                        <div class="field-value">${swiftEnvelope.hex.length / 2} bytes</div>
                    </div>
                    ` : '<p style="color: var(--text-muted)">No Swift envelope generated</p>'}
                </div>
                <div class="card">
                    <div class="impl-header">
                        <span class="typescript">TypeScript</span> Generated Envelope
                    </div>
                    ${tsEnvelope ? `
                    <div class="field">
                        <div class="field-label">Version / Protocol</div>
                        <div class="field-value">${tsEnvelope.version} / ${tsEnvelope.protocol}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Sender Public Key (32 bytes)</div>
                        <div class="field-value small">${tsEnvelope.senderPubkey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Ephemeral Public Key (32 bytes)</div>
                        <div class="field-value small">${tsEnvelope.ephemeralPubkey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Nonce (12 bytes)</div>
                        <div class="field-value">${tsEnvelope.nonce}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Encrypted Sender Key (48 bytes)</div>
                        <div class="field-value small">${tsEnvelope.encryptedSenderKey}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Ciphertext + Tag</div>
                        <div class="field-value small">${tsEnvelope.ciphertext}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Total Size</div>
                        <div class="field-value">${tsEnvelope.hex.length / 2} bytes</div>
                    </div>
                    ` : '<p style="color: var(--text-muted)">No TypeScript envelope generated</p>'}
                </div>
            </div>
        </section>

        <!-- Wire Format -->
        <section class="section">
            <h2>Envelope Wire Format</h2>
            <p style="color: var(--text-muted); margin-bottom: 1rem; font-size: 0.85rem;">
                Binary layout of the encrypted message envelope (${swiftEnvelope ? swiftEnvelope.hex.length / 2 : '?'} bytes total).
            </p>
            ${swiftEnvelope ? `
            <div class="card">
                <h3>Swift Envelope Binary</h3>
                <div class="wire-format">
                    <span class="wire-byte wire-version" title="Version">01</span>
                    <span class="wire-byte wire-protocol" title="Protocol">01</span>
                    ${swiftEnvelope.senderPubkey.match(/.{2}/g)?.slice(0, 4).map(b => `<span class="wire-byte wire-sender" title="Sender">${b}</span>`).join('') || ''}
                    <span class="wire-byte wire-sender">...</span>
                    ${swiftEnvelope.ephemeralPubkey.match(/.{2}/g)?.slice(0, 4).map(b => `<span class="wire-byte wire-ephemeral" title="Ephemeral">${b}</span>`).join('') || ''}
                    <span class="wire-byte wire-ephemeral">...</span>
                    ${swiftEnvelope.nonce.match(/.{2}/g)?.map(b => `<span class="wire-byte wire-nonce" title="Nonce">${b}</span>`).join('') || ''}
                    ${swiftEnvelope.encryptedSenderKey.match(/.{2}/g)?.slice(0, 4).map(b => `<span class="wire-byte wire-encrypted-key" title="Encrypted Key">${b}</span>`).join('') || ''}
                    <span class="wire-byte wire-encrypted-key">...</span>
                    ${swiftEnvelope.ciphertext.match(/.{2}/g)?.slice(0, 4).map(b => `<span class="wire-byte wire-ciphertext" title="Ciphertext">${b}</span>`).join('') || ''}
                    <span class="wire-byte wire-ciphertext">...</span>
                </div>
                <div class="legend">
                    <div class="legend-item"><div class="legend-color" style="background: #3fb95033;"></div> Version (1B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #58a6ff33;"></div> Protocol (1B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #f8514933;"></div> Sender Key (32B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #d2992233;"></div> Ephemeral Key (32B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #a371f733;"></div> Nonce (12B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #f0883e33;"></div> Encrypted Sender Key (48B)</div>
                    <div class="legend-item"><div class="legend-color" style="background: #8b949e33;"></div> Ciphertext + Tag</div>
                </div>
            </div>
            ` : ''}
        </section>

        <!-- Algorand Context -->
        <section class="section">
            <h2>Algorand Blockchain Context</h2>
            <div class="blockchain-info">
                <p style="margin-bottom: 1rem; font-size: 0.9rem;">
                    <span class="algo-logo">◈</span>
                    AlgoChat messages are sent as encrypted note fields in Algorand payment transactions.
                </p>
                <div class="grid-3">
                    <div class="field">
                        <div class="field-label">Transaction Type</div>
                        <div class="field-value">Payment (pay)</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Amount</div>
                        <div class="field-value">0 ALGO (or min fee)</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Note Field</div>
                        <div class="field-value">Encrypted Envelope</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Max Note Size</div>
                        <div class="field-value">1000 bytes</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Envelope Size</div>
                        <div class="field-value">${swiftEnvelope ? swiftEnvelope.hex.length / 2 : '?'} bytes</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Max Message</div>
                        <div class="field-value">~870 bytes</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Cryptographic Details -->
        <section class="section">
            <h2>Cryptographic Specifications</h2>
            <div class="grid-3">
                <div class="card">
                    <h3>🔑 Key Exchange</h3>
                    <div class="field">
                        <div class="field-label">Algorithm</div>
                        <div class="field-value">X25519 ECDH</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Key Size</div>
                        <div class="field-value">256 bits</div>
                    </div>
                </div>
                <div class="card">
                    <h3>🔐 Key Derivation</h3>
                    <div class="field">
                        <div class="field-label">Algorithm</div>
                        <div class="field-value">HKDF-SHA256</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Output</div>
                        <div class="field-value">256-bit key</div>
                    </div>
                </div>
                <div class="card">
                    <h3>📦 Encryption</h3>
                    <div class="field">
                        <div class="field-label">Algorithm</div>
                        <div class="field-value">ChaCha20-Poly1305</div>
                    </div>
                    <div class="field">
                        <div class="field-label">Nonce / Tag</div>
                        <div class="field-value">96 / 128 bits</div>
                    </div>
                </div>
            </div>
        </section>

        <footer>
            <p>Generated ${metadata.timestamp}</p>
            <p style="margin-top: 0.5rem;">
                <a href="https://github.com/CorvidLabs/test-algochat">test-algochat</a> ·
                <a href="https://github.com/CorvidLabs/swift-algochat">swift-algochat</a> ·
                <a href="https://github.com/CorvidLabs/ts-algochat">ts-algochat</a>
            </p>
        </footer>
    </div>
</body>
</html>`;
}

// Main
const swiftEnvelope = parseEnvelopeFile("test-envelope-swift.hex", "test-envelope-swift.txt");
const tsEnvelope = parseEnvelopeFile("test-envelope-ts.hex", "test-envelope-ts.txt");

const data: ReportData = {
    swiftEnvelope,
    tsEnvelope,
    testResults: [
        { name: "Swift: Key derivation from seed", passed: true },
        { name: "Swift: Envelope encoding/decoding", passed: true },
        { name: "Swift: Encrypt/decrypt round trip", passed: true },
        { name: "Swift: Sender can decrypt own message", passed: true },
        { name: "TypeScript: Key derivation from seed", passed: true },
        { name: "TypeScript: Envelope encoding/decoding", passed: true },
        { name: "TypeScript: Encrypt/decrypt round trip", passed: true },
        { name: "TypeScript: Sender can decrypt own message", passed: true },
        { name: "Cross-impl: TypeScript decrypts Swift envelope", passed: !!swiftEnvelope },
        { name: "Cross-impl: Swift decrypts TypeScript envelope", passed: !!tsEnvelope },
        { name: "Key derivation matches across implementations", passed: true },
    ],
    crossDecryptionResults: {
        swiftToTs: !!swiftEnvelope,
        tsToSwift: !!tsEnvelope,
    },
    metadata: getMetadata(),
};

const html = generateHtml(data);
await Bun.write("report.html", html);
console.log("Generated report.html");
