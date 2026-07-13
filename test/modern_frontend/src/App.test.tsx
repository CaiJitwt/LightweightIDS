import { fireEvent, render, screen } from "@testing-library/react";

import App from "./App";

describe("modern IDS frontend", () => {
  it("navigates from the dashboard to alert evidence", async () => {
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Alert Center/ }));

    expect(await screen.findByRole("heading", { name: "Alert center" })).toBeInTheDocument();
    expect(await screen.findByRole("complementary", { name: "Selected alert details" })).toHaveTextContent("Related packets");
    expect(screen.getByText("TLS metadata indicates a weak protocol fingerprint.")).toBeInTheDocument();
  });

  it("filters the traffic table by protocol", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Traffic Monitor" }));
    fireEvent.change(await screen.findByRole("combobox"), { target: { value: "DNS" } });

    expect(screen.getByText("1 packets shown")).toBeInTheDocument();
    expect(screen.getByText("Query A api.internal.example")).toBeInTheDocument();
  });
});
