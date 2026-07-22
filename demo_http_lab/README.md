# HTTP Alert Demo Lab

This classroom page keeps its control UI on local IPv4 loopback, then injects each submitted inert HTTP sample into Scapy's default capture adapter. The frame is addressed back to the same adapter and uses documentation-only IP addresses, so no public target receives it. The receiver never executes, stores, reflects, or forwards submitted content.

## Quick Classroom Setup

1. Start the modern IDS frontend as Administrator:

   ```powershell
   python modern_main.py
   ```

2. In Traffic Monitor, leave **Default interface** selected, enter `tcp.dstport == 8080`, and start capture with packet saving and detection enabled.

3. In a second host terminal, run one command:

   ```powershell
   python demo_http.py
   ```

4. Open the printed address on the same computer: `http://127.0.0.1:8080/`.

5. Click **Send sample** or **Send full sequence**, then inspect Traffic Monitor and Alert Center.

The control server listens only on `127.0.0.1`, while demo samples are injected into the default adapter printed in the terminal. No token, firewall rule, virtual machine, or subnet argument is required. If port `8080` is occupied, run `python demo_http.py --port 8000` or use port `8888`, then update the capture filter to the same port. Use `--interface NAME` when Traffic Monitor is capturing a specific non-default adapter.

## Optional LAN / VM Mode

To send samples from an authorized VM instead, explicitly expose the receiver to the private LAN and restrict the VM subnet:

```powershell
python demo_http.py --host 0.0.0.0 --require-token --allow-network 192.168.118.0/24
```

The terminal prints the available private addresses and complete tokenized URL. A fixed token can be supplied with `--token` when repeatable classroom material is necessary.

## Windows Firewall

Loopback mode needs no firewall rule. Only LAN / VM mode may require this temporary inbound rule from an elevated PowerShell, replacing the subnet with the VM network:

```powershell
New-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -RemoteAddress 192.168.118.0/24
```

Remove it after class:

```powershell
Remove-NetFirewallRule -DisplayName "Lightweight IDS HTTP Demo"
```

## Direct Request

The same computer can submit a benign request without opening the page:

```powershell
curl.exe -X POST "http://127.0.0.1:8080/sink/benign" -H "Content-Type: application/x-www-form-urlencoded" --data "message=demo-health-check&status=ok"
```

The endpoint limits each source to 30 requests per minute and request bodies to 4096 bytes. Predefined scenarios and custom text are injected into the same local self-addressed capture path. Custom text is evaluated by every enabled rule applicable to an HTTP packet and produces alerts for every matching rule. Stateful or non-HTTP rules still require the corresponding packet sequence or protocol.
