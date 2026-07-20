import { beforeEach, expect, it, vi } from "vitest";

import { idsApi } from "../api/idsApi";
import {
  defaultPersonalization,
  loadPersonalization,
  savePersonalization,
  type PersonalizationState,
} from "./personalizationStore";

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

it("prefers project persistence over stale browser personalization", async () => {
  localStorage.setItem(
    "ids-prototype-personalization",
    JSON.stringify({ ...defaultPersonalization, accent: "#aa0000" }),
  );
  const persisted: PersonalizationState = {
    ...defaultPersonalization,
    accent: "#2468ac",
    componentOpacity: 78,
    background: "/api/personalization/images/background?v=42",
  };
  vi.spyOn(idsApi, "personalization").mockResolvedValue({
    state: persisted,
    persisted: true,
  });

  const [loaded, corrupted] = await loadPersonalization();

  expect(corrupted).toBe(false);
  expect(loaded).toEqual(persisted);
  expect(JSON.parse(localStorage.getItem("ids-prototype-personalization") ?? "{}")).toMatchObject({
    accent: "#2468ac",
    componentOpacity: 78,
    background: "/api/personalization/images/background?v=42",
  });
});

it("writes personalization to the project API and browser fallback", async () => {
  const state: PersonalizationState = {
    ...defaultPersonalization,
    tableOpacity: 82,
    tableBlur: 9,
  };
  const save = vi.spyOn(idsApi, "savePersonalization").mockResolvedValue({
    state,
    persisted: true,
  });

  await savePersonalization(state);

  expect(save).toHaveBeenCalledWith(state);
  expect(JSON.parse(localStorage.getItem("ids-prototype-personalization") ?? "{}")).toMatchObject({
    tableOpacity: 82,
    tableBlur: 9,
  });
});
