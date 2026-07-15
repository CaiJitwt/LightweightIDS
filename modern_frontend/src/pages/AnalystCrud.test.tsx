import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import { idsApi } from "../api/idsApi";
import type { AssetRecord, InvestigationRecord } from "../types";
import { AssetsPage } from "./AssetsPage";
import { InvestigationsPage } from "./InvestigationsPage";


afterEach(() => vi.restoreAllMocks());


it("edits and deletes a persisted asset", async () => {
  const asset: AssetRecord = {
    ip: "10.0.0.10",
    display_name: "Database-01",
    role: "Database",
    importance: 85,
    notes: "Primary database",
    created_at: "2026-07-15 10:00:00",
    updated_at: "2026-07-15 10:00:00",
  };
  vi.spyOn(idsApi, "assets").mockResolvedValue({ records: [asset] });
  const update = vi.spyOn(idsApi, "updateAsset").mockResolvedValue({ record: asset });
  const remove = vi.spyOn(idsApi, "deleteAsset").mockResolvedValue({ deleted: true });

  render(<AssetsPage />);
  await screen.findByText("Database-01");
  fireEvent.click(screen.getByTitle("Edit 10.0.0.10"));
  fireEvent.change(screen.getByDisplayValue("Database-01"), { target: { value: "Database-Primary" } });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await waitFor(() => expect(update).toHaveBeenCalledWith("10.0.0.10", expect.objectContaining({ displayName: "Database-Primary" })));
  fireEvent.click(screen.getByTitle("Delete 10.0.0.10"));
  await waitFor(() => expect(remove).toHaveBeenCalledWith("10.0.0.10"));
});


it("edits and deletes a persisted investigation", async () => {
  const record: InvestigationRecord = {
    id: 7,
    title: "Review database activity",
    status: "Open",
    priority: "HIGH",
    host_ip: "10.0.0.10",
    summary: "Validate recent alerts.",
    notes: "Initial notes",
    created_at: "2026-07-15 10:00:00",
    updated_at: "2026-07-15 10:00:00",
  };
  vi.spyOn(idsApi, "investigations").mockResolvedValue({ records: [record] });
  const update = vi.spyOn(idsApi, "updateInvestigation").mockResolvedValue({ record });
  const remove = vi.spyOn(idsApi, "deleteInvestigation").mockResolvedValue({ deleted: true });

  render(<InvestigationsPage />);
  fireEvent.click(await screen.findByText("Review database activity"));
  fireEvent.click(screen.getByTitle("Edit investigation"));
  fireEvent.change(screen.getByDisplayValue("Review database activity"), { target: { value: "Monitor database activity" } });
  fireEvent.change(screen.getByLabelText("Investigation status"), { target: { value: "Monitoring" } });
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

  await waitFor(() => expect(update).toHaveBeenCalledWith(7, expect.objectContaining({ title: "Monitor database activity", status: "Monitoring" })));
  fireEvent.click(screen.getByTitle("Delete investigation"));
  await waitFor(() => expect(remove).toHaveBeenCalledWith(7));
});
