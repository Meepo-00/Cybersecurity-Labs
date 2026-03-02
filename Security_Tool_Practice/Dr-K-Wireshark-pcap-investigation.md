# Dr. K Cybersecurity Lab – Wireshark PCAP Analysis

**Lab source:** Dr. K Cybersecurity (YouTube)
**Environment:** Kali Linux Purple in VMware Workstation Pro
**File:** Provided PCAP file

---

## Objective

A workstation accessed a web server. Did anything suspicious happen? Where was this system trying to go?

---

## Step 1: Filter by HTTP Traffic

Start by filtering for HTTP traffic to reduce noise. HTTP is a good starting point when analyzing PCAP files because it reveals application-layer activity clearly.

Multiple GET requests were visible, all with private IP addresses in the 192.168.x.x range. Packet 46 shows a HTTP GET request for `/tcp-lab/images/localimage.jpg`, originating from **192.168.124.6** on source port **38082**, destined for **192.168.124.7** on destination port **8080**. This request returned a **404 Not Found** response.

> **Key concept:** Most of the time, the client initiates requests to the server — but when it's the other way around, that warrants investigation. Clients initiate; servers respond. If that pattern is reversed, it's a signal worth acting on.

---

## Step 2: Follow the TCP Stream

Right-click packet 46 → **Follow → TCP Stream**

Before trusting any data in a stream, confirm the session is legitimate. **No handshake = no trust.** This principle helps catch spoofed sessions and exploit attempts.

---

## Step 3: Verify the Three-Way Handshake

Right-click packet 46 → **Conversation Filter → TCP**

Navigate to packet 43 and confirm the **TCP three-way handshake** (SYN → SYN-ACK → ACK) is present. Without it, the session cannot be trusted.

---

## Step 4: Analyze TCP Fields

**Sequence Numbers**
When a TCP connection starts (at the SYN packet), both sides choose a random initial sequence number (ISN). This randomness is intentional — if sequence numbers were predictable, attackers could guess them and inject packets into an existing session.

The sequence number is TCP's way of saying: *"We're starting this conversation at this page number — everything else builds from here."*

For SOC analysts, sequence numbers are valuable. They let you determine whether a packet belongs to a given conversation. Out-of-order or anomalous sequence numbers can indicate broken sessions, injection attacks, or manipulation.

**TCP Flags**
TCP flags describe what a packet is doing. **PSH + ACK** together means: *"This packet carries real data — push it immediately to the application layer rather than buffering it."*

**TCP Window Size**
The TCP window size tells you how much data one side is willing to receive before requiring an acknowledgment. Example: a window size of **64,256 bytes** means the receiver is saying "you can send me up to ~64 KB before I need to check in." This is a normal, healthy window size.

- A **small** window size = "hand me one box at a time" (like moving one small box before waiting)
- A **large** window size = "I can handle a lot at once"

Window size is useful for performance context. If traffic feels slow or behaves unexpectedly, this field can help explain why — it reflects congestion control and buffer capacity.

---

## Step 5: Interpret the TCP Stream Colors

In a followed TCP stream, Wireshark uses two colors:
- **Red** = the side that spoke first
- **Blue** = the side that responded

In most HTTP conversations, the client speaks first (red) and the server responds (blue). However, this is not a hard rule in Wireshark — colors can swap depending on how the stream is captured or displayed.

---

## Step 6: Count TCP Segments

An HTTP POST indicates that data was uploaded. Counting how many TCP segments actually carry payload data tells you *how much* data moved and *how* it moved — and that distinction matters.

- A few hundred segments can represent a transferred file
- Normal applications upload data in predictable, consistent patterns
- Attack tools tend not to — they chunk data irregularly, burst, pause, or throttle in ways that stand out not at the byte level, but at the **packet/segment level**

In this case, data was uploaded across **282 TCP segments with payload**. Counting segments answers the question: not just *what* was transferred, but *how* it was transferred.

---

## Step 7: Check Conversations

Go to **Statistics → Conversations** to see the total number of packets and bytes exchanged between client and server. This gives a high-level summary of the full session and helps confirm findings from the stream analysis.
