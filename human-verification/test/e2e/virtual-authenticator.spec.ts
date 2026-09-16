/**
 * Real-browser negative control: Chromium + CDP virtual authenticator (software).
 *
 * Expected: the browser completes both ceremonies, the WebAuthn library accepts the responses, and
 * the strict policy rejects the credential (self-signed "Chromium" attestation chain reaches no
 * trusted anchor), so the form is never accepted and no token is minted. The diagnostic lane shows
 * the same evidence and also never mints a token.
 */
import { test, expect, type Page, type CDPSession } from '@playwright/test';

async function addVirtualAuthenticator(page: Page, opts: { transport?: 'usb' | 'ble' | 'internal' | 'cable'; backup?: boolean } = {}): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: (opts.transport ?? 'internal') as never, // CDP enum: usb|nfc|ble|cable|internal (hybrid = cable)
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: opts.backup ?? false,
      defaultBackupState: opts.backup ?? false,
    },
  });
  return { cdp, authenticatorId };
}

test('virtual authenticator: ceremonies succeed in the browser, strict policy rejects, no acceptance', async ({ page, baseURL }) => {
  await addVirtualAuthenticator(page);
  await page.goto(`${baseURL}/demo/`);
  await page.getByTestId('submit').click();
  await page.waitForURL(/\/verify#s=/);
  await expect(page.getByTestId('session-line')).toContainText('state=pending');

  // First use: enrollment.
  await page.getByTestId('btn-reg').click();
  await expect(page.getByTestId('reg-result')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('reg-result')).toContainText('does not meet the configured authenticator policy');
  await expect(page.getByTestId('policy-outcome').first()).toHaveText('REJECTED');
  const policyText = await page.getByTestId('policy-result').first().innerText();
  expect(policyText).toMatch(/AAGUID_NOT_IN_METADATA|METADATA_UNAVAILABLE|SELF_ATTESTATION|NO_TRUST_ANCHOR|CHAIN_INVALID/);
  expect(policyText).toContain('library.verified');

  // Fresh assertion with the same (untrusted) credential: verified, not approved, no redirect.
  await page.getByTestId('btn-auth').click();
  await expect(page.getByTestId('auth-result')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('auth-result')).toContainText('Not approved');
  expect(page.url()).toContain('/verify#');
  await expect(page.getByTestId('session-line')).toContainText('state=pending');

  // The site backend never accepted anything for this session.
  const sessionId = decodeURIComponent(new URL(page.url()).hash.match(/s=([^&]+)/)![1]!);
  const res = await page.request.get(`${baseURL}/demo/api/submissions/${sessionId}`);
  expect((await res.json()).state).toBe('awaiting-verification');
});

test('diagnostic lane reports evidence for the virtual authenticator and never mints a token', async ({ page, baseURL }) => {
  await addVirtualAuthenticator(page, { backup: true });
  await page.goto(`${baseURL}/diagnostics`);
  await expect(page.getByTestId('policy-summary')).toContainText('"source"');
  await page.getByTestId('diag-reg').click();
  await expect(page.getByTestId('policy-outcome').first()).toHaveText('REJECTED', { timeout: 20_000 });
  const out = await page.getByTestId('out').innerText();
  expect(out).toContain('"approvalToken": null');
  expect(out).toContain('"libraryVerified": true');
  expect(out).toMatch(/"fmt": "(packed|none)"/);
  expect(out).toContain('BACKUP_ELIGIBLE_NOT_HARDWARE_BOUND');
  await page.getByTestId('diag-auth').click();
  await expect(page.getByTestId('out')).toContainText('"approved": false', { timeout: 20_000 });
  await page.getByTestId('diag-save').click();
  await expect(page.locator('#rows')).toContainText('"kind"');
});

test('a forged approval token posted to the site backend is refused', async ({ page, baseURL }) => {
  await page.goto(`${baseURL}/demo/`);
  await page.getByTestId('submit').click();
  await page.waitForURL(/\/verify#s=/);
  const sessionId = decodeURIComponent(new URL(page.url()).hash.match(/s=([^&]+)/)![1]!);
  const res = await page.request.post(`${baseURL}/demo/complete`, { form: { sessionId, approvalToken: 'hvt_forged_forged_forged_forged_forged_forged' } });
  expect(res.status()).toBe(409);
  expect(await res.text()).toContain('Submission not accepted');
});
