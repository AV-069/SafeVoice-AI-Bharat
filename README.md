# 🛡️ Project SafeVoice
**AI-Driven Real-Time Scam Protection for Bharat**

SafeVoice is an intelligent safety layer designed to protect vulnerable populations—specifically senior citizens—from the rising wave of "Digital Arrest" and parcel scams in India. 

## 🚀 The Problem
India lost over ₹120 Crore to digital scams in early 2024 alone. Fraudsters use fear tactics, impersonating police or customs officials, to "digitally arrest" victims. Language barriers and technical complexity make it difficult for seniors to identify these threats in real-time.

## ✨ Key Features
- **Real-Time Analysis:** Streams phone audio to detect scam patterns as they happen.
- **Multilingual Support:** Native support for **Hindi** and **Malayalam** via Azure AI Speech.
- **AI Verdicts:** Uses **Amazon Bedrock (Claude 3)** to understand context and intent, not just keywords.
- **Guardian Alerts:** Automatically notifies registered family members via **Twilio SMS** when a high-risk scam is detected.
- **Senior-First UI:** High-contrast, large-type interface designed for accessibility.

## 🛠️ Technical Stack
- **Frontend:** Next.js (App Router)
- **Database/Auth:** Supabase
- **Speech-to-Text:** Azure AI Speech (Real-time Streaming)
- **Brain (LLM):** Amazon Bedrock (Claude 3 Sonnet)
- **Communications:** Twilio Programmable Messaging API

## 📂 Project Structure
- `/requirements.md`: Detailed functional and non-functional requirements.
- `/design.md`: Technical architecture, database schema, and API flows.
- `/.kiro`: Spec-driven development logs and metadata.

## 🏆 Hackathon
This project is submitted for the **AI for Bharat Hackathon 2026**.
