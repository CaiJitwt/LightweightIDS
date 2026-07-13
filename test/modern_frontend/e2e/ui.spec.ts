import { expect, test } from "@playwright/test";

test("dashboard and alert workflow render without viewport overflow", async ({ page }, testInfo) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "High-risk hosts" })).toBeVisible();

  const viewportOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  expect(viewportOverflow).toBe(false);
  await page.screenshot({ path: testInfo.outputPath("dashboard.png"), fullPage: true });

  await page.getByRole("navigation", { name: "Primary navigation" }).getByRole("button", { name: /Alert Center/ }).click();
  await expect(page.getByRole("complementary", { name: "Selected alert details" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("alerts.png"), fullPage: true });
});
