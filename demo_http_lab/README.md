# HTTP Alert Demo Lab

This classroom page lets a virtual machine send inert plaintext HTTP samples to the IDS host. The receiver discards every request body and never executes, stores, reflects, or forwards submitted content.

## Quick Classroom Setup

1. Start the modern IDS frontend as Administrator:

   ```powershell
   python modern_main.py
   ```

2. In Traffic Monitor, select the adapter connected to the VM, enter `tcp.dstport == 8080`, and start capture with packet saving and detection enabled.

3. In a second host terminal, run one command:

   ```powershell
   python -m demo_http_lab.main
   ```

4. The terminal prints the available private addresses. From the VM, open the address that shares its subnet, for example `http://192.168.118.1:8080/`.

5. Click **Send sample** or **Send full sequence**, then inspect Traffic Monitor and Alert Center.

No token or subnet argument is required in classroom mode. If port `8080` is occupied, start the lab with `--port 8000` or `--port 8888` and use the same port in the capture filter.

## Optional Restrictions

For a less open private-network session, enable a random URL token and restrict the VM subnet:

```powershell
python -m demo_http_lab.main --require-token --allow-network 192.168.118.0/24
```

The terminal then prints the complete tokenized URL. A fixed token can be supplied with `--token` when repeatable classroom material is necessary.

## Windows Firewall

The receiver does not change firewall policy. If Windows blocks the VM, create a temporary inbound rule from an elevated PowerShell, replacing the subnet with the VM network:

```powershell
New-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.118.0/24
```

Remove it after class:

```powershell
Remove-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo"
```

## Direct Request

A VM can submit a benign request without opening the page:

```powershell
curl.exe -X POST "http://192.168.118.1:8080/sink/benign" -H "Content-Type: application/x-www-form-urlencoded" --data "message=demo-health-check&status=ok"
```

The default endpoint still accepts only private-network clients, limits each source to 30 requests per minute, limits request bodies to 4096 bytes, and has no outbound request path.
