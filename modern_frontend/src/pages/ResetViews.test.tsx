import { render, screen, within } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { idsApi } from "../api/idsApi";
import { EventTimelinePage } from "./EventTimelinePage";
import { ReportsPage } from "./ReportsPage";


afterEach(() => vi.restoreAllMocks());


it("shows zero persisted alerts in Reports after reset", async () => {
  vi.spyOn(idsApi, "alerts").mockResolvedValue({ records: [] });
  render(<ReportsPage refreshVersion={1} />);

  const summary = screen.getByText("Total alerts").closest("div");
  expect(summary).not.toBeNull();
  expect(await within(summary as HTMLElement).findByText("0")).toBeInTheDocument();
  expect(screen.queryByText("TLS fingerprint anomaly")).not.toBeInTheDocument();
});


it("shows an empty Event Timeline after reset", async () => {
  vi.spyOn(idsApi, "timeline").mockResolvedValue({ records: [] });
  render(<EventTimelinePage refreshVersion={1} />);

  expect(await screen.findByText("No persisted timeline events match the current filters.")).toBeInTheDocument();
  const alertMetric = screen.getByText("Alerts").closest("div");
  expect(alertMetric).not.toBeNull();
  expect(within(alertMetric as HTMLElement).getByText("0")).toBeInTheDocument();
});
