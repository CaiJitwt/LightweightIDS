# HTTP Alert Demo Lab

This isolated page lets an authorized virtual machine send inert plaintext HTTP samples to the IDS host. The receiver reads each request body only to complete HTTP transport, then discards it. It never executes, stores, evaluates, reflects, or forwards submitted content.

## Recommended VM Setup

Use a host-only virtual network. Find the host address on that network, such as `192.168.56.1`, and the VM subnet, such as `192.168.56.0/24`.

1. Start the modern IDS frontend as Administrator:

   ```powershell
   python modern_main.py
   ```

2. In Traffic Monitor, select the adapter connected to the VM network and use this capture filter:

   ```text
   tcp.dstport == 8080
   ```

3. Start live capture with packet saving and detection enabled.

4. In a second terminal, start the demo receiver:

   ```powershell
   python -m demo_http_lab.main --host 0.0.0.0 --port 8080 --allow-network 192.168.56.0/24 --advertise-host 192.168.56.1
   ```

5. Open the complete URL printed by the receiver in the VM browser. The random token is stored in the URL fragment and must remain present.

6. Send a scenario, then inspect Traffic Monitor and Alert Center on the host.

If port `8080` is occupied, use `8000` or `8888` in both commands and the capture filter. These ports are recognized as plaintext HTTP by the current packet parser. Keep the `dstport` direction so the IDS captures VM-to-host requests without treating the returned page assets as inbound samples.

## Windows Firewall

The receiver never changes firewall policy. If Windows blocks the VM, create a temporary inbound rule from an elevated PowerShell, replacing the subnet with the actual host-only VM subnet:

```powershell
New-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.56.0/24
```

Remove it after the demonstration:

```powershell
Remove-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo"
```

## Direct Request

The terminal prints the current token. A VM can submit a benign request without the page:

```powershell
curl.exe -X POST "http://192.168.56.1:8080/sink/benign" -H "X-Demo-Token: <TOKEN>" -H "Content-Type: application/x-www-form-urlencoded" --data "message=demo-health-check&status=ok"
```

The endpoint accepts only private-network clients by default, limits requests to 30 per minute per source, limits bodies to 4096 bytes, and has no outbound request path.
