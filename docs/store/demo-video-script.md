# 30-second demo video: alert paste to ticket note

The video is optional in the dashboard, which takes a YouTube link. Record at 1280x800 or larger, and use sample data only.

## Setup

1. From the repo root, run:

   ```bash
   python -m http.server 8765
   ```

2. Open `http://localhost:8765/tests/analyst-preview.html?demo=1`. Demo mode makes no lookups, so results appear straight away.
3. Open an empty rich-text box beside it to act as the ticket, with no real ticket or client visible. A blank Word or Google Docs page titled "Ticket INC-4711" works.
4. Have this sample alert ready to paste (from `tests/demo-fixtures.js`):

   ```text
   Securonix INC-4711: svc-backup on BKP-SRV01 signed in from 203.0.113.77, then 198.51.100.23. User clicked hxxps://micros0ft-login[.]example/auth?u=bob and dropped 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f. Firewall alert CVE-2024-3400. DNS 8.8.8.8
   ```

## Script

| Time | On screen | On-screen text | Voice-over |
|---|---|---|---|
| 0:00–0:05 | Empty panel. Paste the alert, and the line "6 indicators found" appears. | Sample data | An alert lands. Paste the whole thing into IOC Triage. |
| 0:05–0:13 | Click **Investigate**. Results fill in. Scroll slowly past a malicious IP and the URL, pausing on the reasons. | Every indicator, one verdict | Every IP, URL, hash and CVE is checked at once, each with a verdict and its reasons. |
| 0:13–0:19 | Scroll back to the top. Hold on **Suggested: Escalate** and its reasons. Choose a value under **Your decision**. | You make the call | It suggests escalate or close, and says why. The decision stays yours. |
| 0:19–0:25 | Click **Copy ticket note**. Switch to the ticket box and paste. The formatted note appears. | One click to the ticket | One click copies the ticket note. Paste it, and the ticket is done. |
| 0:25–0:30 | End card: IOC Triage icon and name. | Free and open source. Lookups send only the indicator. | IOC Triage. Free, open source, and lookups send only the indicator. |

The voice-over is about 60 words, which fits 30 seconds at a steady pace.

## Before you upload

- Check that no real client, ticket, name or browser tab is visible.
- Leave "Sample data" on screen in the first shot, because the verdicts come from fixtures, not live lookups.
- Set the YouTube video to Public or Unlisted. A Private video will not play on the listing.
