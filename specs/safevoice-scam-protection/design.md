# Design Document: Project SafeVoice

## 1. System Architecture Overview

Project SafeVoice is an AI-driven scam protection tool built with a modern serverless architecture:

- **Frontend**: Next.js 14+ (App Router) with React Server Components and Client Components
- **Backend**: Next.js API Routes + Supabase Edge Functions
- **Database**: PostgreSQL (via Supabase)
- **Authentication**: Supabase Auth with Row Level Security (RLS)
- **Speech-to-Text**: Azure AI Speech Services (Real-time transcription)
- **AI Analysis**: Amazon Bedrock (Claude 3 Sonnet for scam detection)
- **Notifications**: Twilio API (SMS alerts to family members)
- **Real-time**: Supabase Realtime subscriptions for live updates

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User's Phone Call                         │
│                    (Audio Stream)                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              SafeVoice Mobile/Web App                        │
│                  (Next.js Frontend)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │Active Monitor│  │   Family     │      │
│  │   Screen     │  │ Alert Screen │  │   Settings   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Next.js API Routes + Supabase                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Audio API   │  │ Analysis API │  │  Alert API   │      │
│  │ /api/audio   │  │ /api/analyze │  │ /api/alert   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Azure     │    │   Amazon     │    │    Twilio    │
│   Speech     │───▶│   Bedrock    │───▶│   SMS API    │
│  Services    │    │  (Claude 3)  │    │              │
└──────────────┘    └──────────────┘    └──────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │    Supabase      │
                    │   PostgreSQL     │
                    │   + Realtime     │
                    └──────────────────┘
```

### Data Flow Sequence

```
1. User starts call monitoring
   ↓
2. Audio captured from phone microphone (3-second chunks)
   ↓
3. Audio sent to Azure Speech-to-Text API
   ↓
4. Azure returns transcribed text (Hindi/Malayalam/English)
   ↓
5. Transcript sent to Amazon Bedrock (Claude 3 Sonnet)
   ↓
6. Bedrock analyzes for scam patterns and returns Risk_Score
   ↓
7. If Risk_Score > 70: Display alert to user
   ↓
8. If Risk_Score > 80: Send SMS to family via Twilio
   ↓
9. Log all data to Supabase for history and analytics
```

## 2. Database Schema (PostgreSQL/Supabase)


### 2.1 Core Tables

```sql
-- Users table (extends Supabase auth.users)
CREATE TABLE public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT UNIQUE,
  full_name TEXT NOT NULL,
  phone_number TEXT NOT NULL,
  preferred_language TEXT NOT NULL CHECK (preferred_language IN ('hindi', 'malayalam', 'english')),
  alert_sensitivity TEXT DEFAULT 'medium' CHECK (alert_sensitivity IN ('low', 'medium', 'high')),
  auto_family_alerts BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Trusted contacts (family members)
CREATE TABLE public.trusted_contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  contact_name TEXT NOT NULL,
  contact_phone TEXT NOT NULL,
  relationship TEXT,
  is_verified BOOLEAN DEFAULT FALSE,
  verification_code TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT max_contacts CHECK (
    (SELECT COUNT(*) FROM public.trusted_contacts WHERE user_id = user_id) <= 5
  )
);

-- Scam logs (call monitoring records)
CREATE TABLE public.scam_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  call_started_at TIMESTAMPTZ NOT NULL,
  call_ended_at TIMESTAMPTZ,
  duration_seconds INTEGER,
  transcription TEXT,
  detected_language TEXT,
  scam_type TEXT CHECK (scam_type IN ('digital_arrest', 'parcel_scam', 'other', 'none')),
  risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  confidence_level NUMERIC(3,2),
  detected_patterns JSONB,
  alert_triggered BOOLEAN DEFAULT FALSE,
  family_notified BOOLEAN DEFAULT FALSE,
  user_feedback TEXT CHECK (user_feedback IN ('correct', 'false_alarm', NULL)),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Language preferences (for multi-language support)
CREATE TABLE public.language_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE UNIQUE,
  ui_language TEXT NOT NULL CHECK (ui_language IN ('hindi', 'malayalam', 'english')),
  speech_language TEXT NOT NULL CHECK (speech_language IN ('hi-IN', 'ml-IN', 'en-IN')),
  auto_detect_language BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert notifications log
CREATE TABLE public.alert_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scam_log_id UUID REFERENCES public.scam_logs(id) ON DELETE CASCADE,
  recipient_id UUID REFERENCES public.trusted_contacts(id),
  recipient_phone TEXT NOT NULL,
  message_body TEXT NOT NULL,
  delivery_status TEXT CHECK (delivery_status IN ('pending', 'sent', 'failed')),
  twilio_sid TEXT,
  sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scam patterns dictionary (for offline mode)
CREATE TABLE public.scam_patterns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pattern_type TEXT NOT NULL CHECK (pattern_type IN ('digital_arrest', 'parcel_scam', 'other')),
  language TEXT NOT NULL CHECK (language IN ('hindi', 'malayalam', 'english')),
  keywords JSONB NOT NULL,
  phrases JSONB NOT NULL,
  weight INTEGER DEFAULT 1,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- User feedback for model improvement
CREATE TABLE public.user_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scam_log_id UUID REFERENCES public.scam_logs(id) ON DELETE CASCADE,
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  feedback_type TEXT CHECK (feedback_type IN ('correct_detection', 'false_alarm', 'missed_scam', 'new_scam_type')),
  comments TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- System configuration
CREATE TABLE public.system_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_key TEXT UNIQUE NOT NULL,
  config_value JSONB NOT NULL,
  description TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### 2.2 Indexes for Performance

```sql
CREATE INDEX idx_scam_logs_user_id ON public.scam_logs(user_id);
CREATE INDEX idx_scam_logs_risk_score ON public.scam_logs(risk_score);
CREATE INDEX idx_scam_logs_created_at ON public.scam_logs(created_at);
CREATE INDEX idx_trusted_contacts_user_id ON public.trusted_contacts(user_id);
CREATE INDEX idx_alert_notifications_scam_log_id ON public.alert_notifications(scam_log_id);
CREATE INDEX idx_scam_patterns_language ON public.scam_patterns(language, pattern_type);
```

### 2.3 Row Level Security (RLS) Policies

```sql
-- Enable RLS on all tables
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trusted_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.language_preferences ENABLE ROW LEVEL SECURITY;

-- Users can only view and edit their own data
CREATE POLICY "Users view own profile" ON public.users
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users update own profile" ON public.users
  FOR UPDATE USING (auth.uid() = id);

-- Users can only manage their own trusted contacts
CREATE POLICY "Users manage own contacts" ON public.trusted_contacts
  FOR ALL USING (user_id = auth.uid());

-- Users can only view their own scam logs
CREATE POLICY "Users view own scam logs" ON public.scam_logs
  FOR SELECT USING (user_id = auth.uid());

-- Users can only manage their own language preferences
CREATE POLICY "Users manage own language prefs" ON public.language_preferences
  FOR ALL USING (user_id = auth.uid());
```

## 3. API Integration Flows

### 3.1 Azure Speech-to-Text Integration

**Purpose**: Real-time transcription of phone call audio in Hindi, Malayalam, and English.

**Configuration**:
```typescript
// lib/azure-speech.ts
import * as sdk from 'microsoft-cognitiveservices-speech-sdk';

const speechConfig = sdk.SpeechConfig.fromSubscription(
  process.env.AZURE_SPEECH_KEY!,
  process.env.AZURE_SPEECH_REGION!
);

export function createRecognizer(language: string) {
  // Set language based on user preference
  speechConfig.speechRecognitionLanguage = language; // 'hi-IN', 'ml-IN', or 'en-IN'
  
  const audioConfig = sdk.AudioConfig.fromDefaultMicrophone();
  const recognizer = new sdk.SpeechRecognizer(speechConfig, audioConfig);
  
  return recognizer;
}
```

**Audio Streaming Flow**:
```
1. User starts call monitoring
   ↓
2. Frontend captures audio from microphone
   ↓
3. Audio buffered in 3-second chunks
   ↓
4. API Route: /api/audio/stream
   ↓
5. Audio sent to Azure Speech Services (continuous recognition mode)
   ↓
6. Azure returns partial transcripts in real-time
   ↓
7. Transcripts accumulated and sent to analysis pipeline
   ↓
8. Final transcript saved to database
```

**API Endpoint Design**:
```typescript
// app/api/audio/stream/route.ts
import { createRecognizer } from '@/lib/azure-speech';

export async function POST(request: Request) {
  try {
    const { audioChunk, language, userId, sessionId } = await request.json();
    
    // Create recognizer for specified language
    const recognizer = createRecognizer(language);
    
    let fullTranscript = '';
    
    // Set up continuous recognition
    recognizer.recognizing = (s, e) => {
      console.log(`Recognizing: ${e.result.text}`);
    };
    
    recognizer.recognized = async (s, e) => {
      if (e.result.reason === sdk.ResultReason.RecognizedSpeech) {
        fullTranscript += e.result.text + ' ';
        
        // Send transcript chunk to analysis
        await analyzeTranscript(fullTranscript, userId, sessionId);
      }
    };
    
    recognizer.canceled = (s, e) => {
      console.error(`Recognition canceled: ${e.errorDetails}`);
      recognizer.stopContinuousRecognitionAsync();
    };
    
    // Start continuous recognition
    await recognizer.startContinuousRecognitionAsync();
    
    return Response.json({ 
      success: true, 
      sessionId,
      message: 'Audio streaming started' 
    });
    
  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500 });
  }
}
```


### 3.2 Amazon Bedrock Integration (Claude 3 Sonnet)

**Purpose**: AI-powered analysis of transcribed conversations to detect scam patterns.

**Configuration**:
```typescript
// lib/bedrock.ts
import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";

const bedrockClient = new BedrockRuntimeClient({
  region: process.env.AWS_REGION!,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  },
});

export async function analyzeScamPatterns(transcript: string, language: string) {
  const prompt = `You are a scam detection expert analyzing phone conversations in ${language}.

Analyze the following conversation transcript and determine if it contains scam indicators:

Transcript: "${transcript}"

Look for these scam types:
1. Digital Arrest Scam: Impersonation of police/law enforcement, threats of arrest, demands for immediate payment, mentions of warrants or legal action
2. Parcel Scam: Fake delivery notifications, requests for customs payment, demands for OTP or personal information, package held claims

Provide your analysis in the following JSON format:
{
  "risk_score": <0-100>,
  "scam_type": "digital_arrest" | "parcel_scam" | "other" | "none",
  "confidence_level": <0.00-1.00>,
  "detected_patterns": ["pattern1", "pattern2"],
  "reasoning": "Brief explanation of why this is/isn't a scam",
  "key_phrases": ["suspicious phrase 1", "suspicious phrase 2"]
}`;

  const command = new InvokeModelCommand({
    modelId: "anthropic.claude-3-sonnet-20240229-v1:0",
    contentType: "application/json",
    accept: "application/json",
    body: JSON.stringify({
      anthropic_version: "bedrock-2023-05-31",
      max_tokens: 1000,
      temperature: 0.3,
      messages: [
        {
          role: "user",
          content: prompt
        }
      ]
    })
  });

  try {
    const response = await bedrockClient.send(command);
    const responseBody = JSON.parse(new TextDecoder().decode(response.body));
    
    // Extract JSON from Claude's response
    const analysisText = responseBody.content[0].text;
    const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
    
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    throw new Error('Failed to parse Bedrock response');
    
  } catch (error) {
    console.error('Bedrock analysis error:', error);
    throw error;
  }
}
```

**Analysis Flow**:
```
1. Transcript received from Azure Speech-to-Text
   ↓
2. API Route: /api/analyze/scam
   ↓
3. Format prompt with transcript and language context
   ↓
4. Send to Amazon Bedrock (Claude 3 Sonnet)
   ↓
5. Bedrock analyzes conversation for scam patterns
   ↓
6. Parse response: risk_score, scam_type, confidence, patterns
   ↓
7. If risk_score > 70: Trigger user alert
   ↓
8. If risk_score > 80: Trigger family SMS alerts
   ↓
9. Save analysis to scam_logs table
```

**API Endpoint Design**:
```typescript
// app/api/analyze/scam/route.ts
import { analyzeScamPatterns } from '@/lib/bedrock';
import { createClient } from '@/lib/supabase/server';

export async function POST(request: Request) {
  try {
    const { transcript, language, userId, sessionId } = await request.json();
    
    // Analyze with Bedrock
    const analysis = await analyzeScamPatterns(transcript, language);
    
    const supabase = createClient();
    
    // Save to database
    const { data: scamLog, error } = await supabase
      .from('scam_logs')
      .insert({
        user_id: userId,
        transcription: transcript,
        detected_language: language,
        scam_type: analysis.scam_type,
        risk_score: analysis.risk_score,
        confidence_level: analysis.confidence_level,
        detected_patterns: analysis.detected_patterns,
        alert_triggered: analysis.risk_score > 70,
        call_started_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error) throw error;
    
    // Trigger alerts if needed
    if (analysis.risk_score > 70) {
      // Send real-time alert to user via Supabase Realtime
      await supabase
        .channel(`user_${userId}`)
        .send({
          type: 'broadcast',
          event: 'scam_alert',
          payload: {
            scamLogId: scamLog.id,
            riskScore: analysis.risk_score,
            scamType: analysis.scam_type,
            keyPhrases: analysis.key_phrases
          }
        });
    }
    
    if (analysis.risk_score > 80) {
      // Trigger family SMS alerts
      await fetch('/api/alert/family', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          scamLogId: scamLog.id,
          scamType: analysis.scam_type,
          riskScore: analysis.risk_score
        })
      });
    }
    
    return Response.json({
      success: true,
      analysis,
      scamLogId: scamLog.id
    });
    
  } catch (error) {
    // Fallback to rule-based detection if Bedrock fails
    console.error('Bedrock analysis failed, using fallback:', error);
    
    const fallbackAnalysis = await ruleBasedDetection(transcript, language);
    
    return Response.json({
      success: true,
      analysis: fallbackAnalysis,
      fallback: true
    });
  }
}

// Fallback rule-based detection for offline/error scenarios
async function ruleBasedDetection(transcript: string, language: string) {
  const supabase = createClient();
  
  // Fetch scam patterns from database
  const { data: patterns } = await supabase
    .from('scam_patterns')
    .select('*')
    .eq('language', language)
    .eq('is_active', true);
  
  let riskScore = 0;
  const detectedPatterns = [];
  
  for (const pattern of patterns || []) {
    const keywords = pattern.keywords as string[];
    const phrases = pattern.phrases as string[];
    
    // Check for keyword matches
    for (const keyword of keywords) {
      if (transcript.toLowerCase().includes(keyword.toLowerCase())) {
        riskScore += pattern.weight * 10;
        detectedPatterns.push(keyword);
      }
    }
    
    // Check for phrase matches
    for (const phrase of phrases) {
      if (transcript.toLowerCase().includes(phrase.toLowerCase())) {
        riskScore += pattern.weight * 15;
        detectedPatterns.push(phrase);
      }
    }
  }
  
  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);
  
  return {
    risk_score: riskScore,
    scam_type: riskScore > 70 ? 'other' : 'none',
    confidence_level: 0.6,
    detected_patterns: detectedPatterns,
    reasoning: 'Rule-based detection (offline mode)',
    key_phrases: detectedPatterns
  };
}
```


### 3.3 Twilio SMS Alert Integration

**Purpose**: Send automated SMS alerts to family members when high-risk scams are detected.

**Configuration**:
```typescript
// lib/twilio.ts
import twilio from 'twilio';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

export const twilioClient = twilio(accountSid, authToken);

export async function sendFamilyAlert(
  recipientPhone: string,
  userName: string,
  scamType: string,
  riskScore: number,
  timestamp: string
) {
  const scamTypeDisplay = {
    digital_arrest: 'Digital Arrest Scam',
    parcel_scam: 'Parcel Scam',
    other: 'Suspicious Call'
  }[scamType] || 'Suspicious Call';
  
  const messageBody = `🚨 SafeVoice Alert: ${userName} may be receiving a ${scamTypeDisplay} call (Risk: ${riskScore}/100) at ${timestamp}. Please check on them immediately. View details: [APP_LINK]`;
  
  try {
    const message = await twilioClient.messages.create({
      body: messageBody,
      from: twilioPhone,
      to: recipientPhone
    });
    
    return {
      success: true,
      sid: message.sid,
      status: message.status
    };
  } catch (error) {
    console.error('Twilio SMS error:', error);
    throw error;
  }
}
```

**Alert Flow**:
```
1. Scam detected with risk_score > 80
   ↓
2. API Route: /api/alert/family
   ↓
3. Fetch user's trusted contacts from database
   ↓
4. For each verified contact:
   - Format SMS message with scam details
   - Send via Twilio API
   - Log delivery status
   ↓
5. Retry failed messages up to 3 times
   ↓
6. Update scam_log with family_notified = true
```

**API Endpoint Design**:
```typescript
// app/api/alert/family/route.ts
import { sendFamilyAlert } from '@/lib/twilio';
import { createClient } from '@/lib/supabase/server';

export async function POST(request: Request) {
  try {
    const { userId, scamLogId, scamType, riskScore } = await request.json();
    
    const supabase = createClient();
    
    // Fetch user details
    const { data: user } = await supabase
      .from('users')
      .select('full_name, auto_family_alerts')
      .eq('id', userId)
      .single();
    
    if (!user?.auto_family_alerts) {
      return Response.json({ 
        success: false, 
        message: 'Auto alerts disabled' 
      });
    }
    
    // Fetch verified trusted contacts
    const { data: contacts } = await supabase
      .from('trusted_contacts')
      .select('*')
      .eq('user_id', userId)
      .eq('is_verified', true);
    
    if (!contacts || contacts.length === 0) {
      return Response.json({ 
        success: false, 
        message: 'No verified contacts' 
      });
    }
    
    const timestamp = new Date().toLocaleString('en-IN', { 
      timeZone: 'Asia/Kolkata' 
    });
    
    const results = [];
    
    // Send SMS to each contact with retry logic
    for (const contact of contacts) {
      let attempts = 0;
      let success = false;
      let lastError = null;
      
      while (attempts < 3 && !success) {
        try {
          const result = await sendFamilyAlert(
            contact.contact_phone,
            user.full_name,
            scamType,
            riskScore,
            timestamp
          );
          
          // Log successful notification
          await supabase.from('alert_notifications').insert({
            scam_log_id: scamLogId,
            recipient_id: contact.id,
            recipient_phone: contact.contact_phone,
            message_body: result.messageBody,
            delivery_status: 'sent',
            twilio_sid: result.sid,
            sent_at: new Date().toISOString()
          });
          
          success = true;
          results.push({ contact: contact.contact_name, success: true });
          
        } catch (error) {
          lastError = error;
          attempts++;
          
          if (attempts < 3) {
            // Exponential backoff: 1s, 2s, 4s
            await new Promise(resolve => 
              setTimeout(resolve, Math.pow(2, attempts) * 1000)
            );
          }
        }
      }
      
      if (!success) {
        // Log failed notification
        await supabase.from('alert_notifications').insert({
          scam_log_id: scamLogId,
          recipient_id: contact.id,
          recipient_phone: contact.contact_phone,
          message_body: 'Failed to send',
          delivery_status: 'failed'
        });
        
        results.push({ 
          contact: contact.contact_name, 
          success: false, 
          error: lastError.message 
        });
      }
    }
    
    // Update scam log
    await supabase
      .from('scam_logs')
      .update({ family_notified: true })
      .eq('id', scamLogId);
    
    return Response.json({
      success: true,
      results,
      totalContacts: contacts.length,
      successCount: results.filter(r => r.success).length
    });
    
  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500 });
  }
}
```


## 4. UI Structure - 3 Core Screens

### 4.1 Dashboard Screen

**Route**: `/dashboard`

**Purpose**: Main landing screen showing call history, statistics, and quick access to monitoring.

**SafeVoice Branding**:
- Primary Color: #FF6B6B (Alert Red)
- Secondary Color: #4ECDC4 (Trust Teal)
- Background: #F7F7F7 (Light Gray)
- Text: #2C3E50 (Dark Blue-Gray)
- Font: Inter (sans-serif, highly readable)

**Components**:

1. **Header Section**:
   - SafeVoice logo with shield icon
   - User greeting: "नमस्ते, [Name]" (in selected language)
   - Language selector dropdown (Hindi/Malayalam/English)
   - Settings icon (top-right)

2. **Quick Action Card** (Prominent, centered):
   - Large circular button: "Start Monitoring" / "निगरानी शुरू करें"
   - Icon: Microphone with shield
   - Size: 120x120px, high contrast
   - Status indicator: Green (ready) / Red (active)

3. **Statistics Dashboard**:
   - Total Calls Monitored (large number, 32pt font)
   - Scams Detected (red badge)
   - Safe Calls (green badge)
   - This Week's Activity (simple bar chart)

4. **Recent Call History** (Scrollable list):
   - Each item shows:
     - Date & Time
     - Duration
     - Risk indicator (color-coded circle: green/yellow/red)
     - Scam type (if detected)
     - Tap to view details
   - Maximum 10 recent calls displayed

5. **Emergency Help Button** (Bottom, always visible):
   - Red button: "Emergency Help" / "आपातकालीन सहायता"
   - Icon: Phone with SOS
   - One-tap access to emergency contacts

**Layout (Mobile-First)**:
```
┌─────────────────────────────────────┐
│  SafeVoice 🛡️        [Lang] [⚙️]   │
│  नमस्ते, राज जी                     │
├─────────────────────────────────────┤
│                                     │
│         ┌─────────────┐             │
│         │             │             │
│         │   🎤 START  │             │
│         │  MONITORING │             │
│         │             │             │
│         └─────────────┘             │
│                                     │
├─────────────────────────────────────┤
│  📊 Statistics                      │
│  ┌─────┐ ┌─────┐ ┌─────┐           │
│  │ 45  │ │  3  │ │ 42  │           │
│  │Calls│ │Scams│ │Safe │           │
│  └─────┘ └─────┘ └─────┘           │
├─────────────────────────────────────┤
│  📞 Recent Calls                    │
│  ┌─────────────────────────────┐   │
│  │ 🟢 Today, 2:30 PM           │   │
│  │    Safe Call (2m 15s)       │   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │ 🔴 Yesterday, 11:45 AM      │   │
│  │    Digital Arrest (Risk: 85)│   │
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │ 🟡 Dec 10, 4:20 PM          │   │
│  │    Suspicious (Risk: 65)    │   │
│  └─────────────────────────────┘   │
├─────────────────────────────────────┤
│     🚨 EMERGENCY HELP 🚨            │
└─────────────────────────────────────┘
```

**Data Fetching**:
```typescript
// app/dashboard/page.tsx
import { createClient } from '@/lib/supabase/server';

export default async function DashboardPage() {
  const supabase = createClient();
  
  const { data: { user } } = await supabase.auth.getUser();
  
  // Fetch user profile
  const { data: profile } = await supabase
    .from('users')
    .select('full_name, preferred_language')
    .eq('id', user.id)
    .single();
  
  // Fetch call statistics
  const { data: scamLogs } = await supabase
    .from('scam_logs')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(10);
  
  const totalCalls = scamLogs?.length || 0;
  const scamsDetected = scamLogs?.filter(log => log.risk_score > 70).length || 0;
  const safeCalls = totalCalls - scamsDetected;
  
  return (
    <DashboardUI 
      profile={profile}
      stats={{ totalCalls, scamsDetected, safeCalls }}
      recentCalls={scamLogs}
    />
  );
}
```


### 4.2 Active Monitor / Alert Screen

**Route**: `/monitor`

**Purpose**: Real-time call monitoring with live transcription and instant scam alerts.

**Components**:

1. **Monitoring Status Header**:
   - Large status indicator: "Monitoring Active" / "निगरानी सक्रिय"
   - Animated pulse effect on microphone icon
   - Call duration timer (MM:SS)
   - Stop button (prominent, red)

2. **Live Transcription Panel**:
   - Scrollable text area showing real-time transcript
   - Font size: 20pt for readability
   - Auto-scroll to latest text
   - Language indicator badge

3. **Risk Meter** (Visual indicator):
   - Horizontal bar or circular gauge
   - Color gradient: Green (0-40) → Yellow (41-70) → Red (71-100)
   - Large number display of current risk score
   - Updates in real-time as conversation progresses

4. **Alert Overlay** (Triggered when risk_score > 70):
   - Full-screen modal with semi-transparent red background
   - Large warning icon (⚠️)
   - Alert message in user's language:
     - "SCAM DETECTED!" / "घोटाला पकड़ा गया!"
     - Scam type: "Digital Arrest Scam"
     - Risk score: "85/100"
     - Key warning phrases detected
   - Action buttons (large, 56px height):
     - "End Call Now" (primary, red)
     - "Report Scam" (secondary)
     - "False Alarm" (tertiary, small)
   - Vibration + sound alert

5. **Quick Actions Bar** (Bottom):
   - Mute/Unmute button
   - Pause monitoring button
   - View transcript history button

**Layout (Active Monitoring)**:
```
┌─────────────────────────────────────┐
│  🎤 MONITORING ACTIVE               │
│  Duration: 02:35                    │
│  [STOP MONITORING]                  │
├─────────────────────────────────────┤
│  📝 Live Transcript (Hindi)         │
│  ┌─────────────────────────────┐   │
│  │ "नमस्ते, मैं पुलिस से बोल   │   │
│  │  रहा हूं। आपके नाम पर एक    │   │
│  │  वारंट जारी हुआ है..."      │   │
│  │                             │   │
│  │  [Auto-scrolling text...]   │   │
│  └─────────────────────────────┘   │
├─────────────────────────────────────┤
│  ⚠️ Risk Level                      │
│  ┌─────────────────────────────┐   │
│  │ ████████████░░░░░░░░░░░░░░  │   │
│  │         85 / 100            │   │
│  └─────────────────────────────┘   │
├─────────────────────────────────────┤
│  [🔇]  [⏸️]  [📄]                   │
└─────────────────────────────────────┘
```

**Layout (Alert Triggered)**:
```
┌─────────────────────────────────────┐
│                                     │
│         ⚠️  ALERT  ⚠️               │
│                                     │
│     SCAM DETECTED!                  │
│     घोटाला पकड़ा गया!               │
│                                     │
│  Type: Digital Arrest Scam          │
│  Risk Score: 85/100                 │
│                                     │
│  Warning Signs:                     │
│  • "पुलिस से बोल रहा हूं"          │
│  • "वारंट जारी हुआ है"             │
│  • "तुरंत पैसे भेजें"               │
│                                     │
│  ┌─────────────────────────────┐   │
│  │   🚨 END CALL NOW 🚨        │   │
│  └─────────────────────────────┘   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │     Report Scam             │   │
│  └─────────────────────────────┘   │
│                                     │
│        [False Alarm]                │
│                                     │
└─────────────────────────────────────┘
```

**Real-time Updates with Supabase**:
```typescript
// app/monitor/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { createClient } from '@/lib/supabase/client';

export default function MonitorPage() {
  const [transcript, setTranscript] = useState('');
  const [riskScore, setRiskScore] = useState(0);
  const [alertVisible, setAlertVisible] = useState(false);
  const [scamDetails, setScamDetails] = useState(null);
  
  const supabase = createClient();
  
  useEffect(() => {
    // Subscribe to real-time scam alerts
    const channel = supabase
      .channel(`user_${userId}`)
      .on('broadcast', { event: 'scam_alert' }, (payload) => {
        setScamDetails(payload);
        setAlertVisible(true);
        
        // Trigger vibration and sound
        if (navigator.vibrate) {
          navigator.vibrate([200, 100, 200, 100, 200]);
        }
        
        const audio = new Audio('/alert-sound.mp3');
        audio.play();
      })
      .subscribe();
    
    return () => {
      supabase.removeChannel(channel);
    };
  }, []);
  
  const handleEndCall = async () => {
    // Stop monitoring
    await fetch('/api/audio/stop', {
      method: 'POST',
      body: JSON.stringify({ sessionId })
    });
    
    // Navigate back to dashboard
    router.push('/dashboard');
  };
  
  return (
    <>
      <MonitoringUI 
        transcript={transcript}
        riskScore={riskScore}
        onStop={handleEndCall}
      />
      
      {alertVisible && (
        <AlertOverlay 
          scamDetails={scamDetails}
          onEndCall={handleEndCall}
          onReport={() => {/* Report logic */}}
          onFalseAlarm={() => setAlertVisible(false)}
        />
      )}
    </>
  );
}
```


### 4.3 Family Settings Screen

**Route**: `/settings/family`

**Purpose**: Manage trusted family contacts who receive SMS alerts when scams are detected.

**Components**:

1. **Header Section**:
   - Title: "Family Contacts" / "परिवार संपर्क"
   - Subtitle: "Add up to 5 trusted contacts"
   - Back button to settings

2. **Auto-Alert Toggle**:
   - Large toggle switch
   - Label: "Automatically alert family when scam detected"
   - Description text explaining the feature

3. **Contact List** (Scrollable):
   - Each contact card shows:
     - Contact name (24pt font)
     - Phone number
     - Relationship (optional)
     - Verification status badge (✓ Verified / ⏳ Pending)
     - Edit and Delete buttons (icon-based)
   - Empty state: "No contacts added yet"

4. **Add Contact Button** (Prominent):
   - Large button: "+ Add Family Contact"
   - Opens modal/form for adding new contact

5. **Add Contact Form** (Modal):
   - Input fields (large, 48px height):
     - Name (required)
     - Phone number (required, with country code)
     - Relationship (optional dropdown)
   - Verification notice: "SMS verification will be sent"
   - Save button

6. **Alert Sensitivity Setting**:
   - Radio buttons (large touch targets):
     - Low (Risk > 85)
     - Medium (Risk > 70) [Default]
     - High (Risk > 60)
   - Description of each level

**Layout**:
```
┌─────────────────────────────────────┐
│  ← Family Contacts                  │
│  Add up to 5 trusted contacts       │
├─────────────────────────────────────┤
│  Auto-Alert Family                  │
│  ┌─────────────────────────────┐   │
│  │ [●────────] ON              │   │
│  └─────────────────────────────┘   │
│  Alert family when scam detected    │
├─────────────────────────────────────┤
│  👥 Your Contacts (2/5)             │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ राज कुमार (बेटा)            │   │
│  │ +91 98765 43210             │   │
│  │ ✓ Verified      [✏️] [🗑️]   │   │
│  └─────────────────────────────┘   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ प्रिया शर्मा (बेटी)          │   │
│  │ +91 98765 43211             │   │
│  │ ⏳ Pending      [✏️] [🗑️]   │   │
│  └─────────────────────────────┘   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │   + Add Family Contact      │   │
│  └─────────────────────────────┘   │
├─────────────────────────────────────┤
│  ⚙️ Alert Sensitivity               │
│  ○ Low (Risk > 85)                  │
│  ● Medium (Risk > 70)               │
│  ○ High (Risk > 60)                 │
└─────────────────────────────────────┘
```

**Add Contact Modal**:
```
┌─────────────────────────────────────┐
│  Add Family Contact                 │
├─────────────────────────────────────┤
│                                     │
│  Name *                             │
│  ┌─────────────────────────────┐   │
│  │ Enter name                  │   │
│  └─────────────────────────────┘   │
│                                     │
│  Phone Number *                     │
│  ┌─────────────────────────────┐   │
│  │ +91 |                       │   │
│  └─────────────────────────────┘   │
│                                     │
│  Relationship                       │
│  ┌─────────────────────────────┐   │
│  │ Select ▼                    │   │
│  └─────────────────────────────┘   │
│  (Son, Daughter, Spouse, etc.)      │
│                                     │
│  ℹ️ SMS verification will be sent   │
│                                     │
│  ┌─────────────────────────────┐   │
│  │      Save Contact           │   │
│  └─────────────────────────────┘   │
│                                     │
│           [Cancel]                  │
│                                     │
└─────────────────────────────────────┘
```

**Data Management**:
```typescript
// app/settings/family/page.tsx
import { createClient } from '@/lib/supabase/server';

export default async function FamilySettingsPage() {
  const supabase = createClient();
  const { data: { user } } = await supabase.auth.getUser();
  
  // Fetch user settings
  const { data: userSettings } = await supabase
    .from('users')
    .select('auto_family_alerts, alert_sensitivity')
    .eq('id', user.id)
    .single();
  
  // Fetch trusted contacts
  const { data: contacts } = await supabase
    .from('trusted_contacts')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false });
  
  return (
    <FamilySettingsUI 
      settings={userSettings}
      contacts={contacts}
      maxContacts={5}
    />
  );
}

// API endpoint for adding contacts
// app/api/contacts/add/route.ts
export async function POST(request: Request) {
  const { userId, name, phone, relationship } = await request.json();
  
  const supabase = createClient();
  
  // Check contact limit
  const { count } = await supabase
    .from('trusted_contacts')
    .select('*', { count: 'exact', head: true })
    .eq('user_id', userId);
  
  if (count >= 5) {
    return Response.json({ 
      error: 'Maximum 5 contacts allowed' 
    }, { status: 400 });
  }
  
  // Generate verification code
  const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Insert contact
  const { data: contact, error } = await supabase
    .from('trusted_contacts')
    .insert({
      user_id: userId,
      contact_name: name,
      contact_phone: phone,
      relationship,
      verification_code: verificationCode,
      is_verified: false
    })
    .select()
    .single();
  
  if (error) throw error;
  
  // Send verification SMS via Twilio
  await twilioClient.messages.create({
    body: `SafeVoice: Your verification code is ${verificationCode}. Enter this code to complete setup.`,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone
  });
  
  return Response.json({ success: true, contact });
}
```


## 5. Security and Privacy Considerations

### 5.1 Data Encryption
- All audio data encrypted in transit using TLS 1.3
- Transcripts encrypted at rest in Supabase using AES-256
- PII anonymized before sending to Amazon Bedrock
- No raw audio files stored after transcription

### 5.2 Authentication and Authorization
- Supabase Auth with JWT tokens
- Row Level Security (RLS) policies enforce data isolation
- Users can only access their own data
- Service role keys for backend operations only

### 5.3 Privacy Compliance
- Audio capture requires explicit user consent
- Users can delete call history at any time
- Data retention: 90 days (configurable)
- GDPR-compliant data deletion on account closure

### 5.4 API Security
- Azure Speech API keys stored in environment variables
- AWS credentials for Bedrock secured with IAM roles
- Twilio credentials encrypted and rotated regularly
- Rate limiting on all API endpoints

## 6. Performance Optimization

### 6.1 Real-time Processing
- Audio buffered in 3-second chunks for efficiency
- Parallel processing: Transcription + Analysis
- WebSocket connections for live updates
- Optimistic UI updates for better UX

### 6.2 Offline Fallback
- Rule-based detection cached locally
- Scam pattern dictionary pre-loaded
- Queue API requests when offline
- Sync when connectivity restored

### 6.3 Cost Optimization
- Batch API requests where possible
- Cache frequently accessed data
- Implement request throttling
- Monitor API usage and set budget alerts

## 7. Accessibility Features

### 7.1 Visual Accessibility
- WCAG AAA contrast ratios (7:1 minimum)
- Minimum font size: 18pt body, 24pt headings
- High contrast mode option
- Adjustable text size (18pt - 32pt)

### 7.2 Motor Accessibility
- Large touch targets (minimum 48x48px)
- Generous spacing between interactive elements
- Voice commands for primary actions
- One-handed operation support

### 7.3 Cognitive Accessibility
- Simple, clear language
- Maximum 5 options per screen
- Consistent navigation patterns
- Visual feedback for all actions

### 7.4 Assistive Technology Support
- Screen reader compatibility (ARIA labels)
- Haptic feedback for alerts
- Text-to-speech for notifications
- Keyboard navigation support

## 8. Multi-Language Implementation

### 8.1 Supported Languages
- Hindi (hi-IN): Primary target audience
- Malayalam (ml-IN): Secondary target audience
- English (en-IN): Fallback and urban users

### 8.2 Language Detection
- Auto-detect from audio using Azure Speech
- User can manually select preferred language
- Language-specific scam pattern databases
- Localized UI strings for all screens

### 8.3 Translation Strategy
```typescript
// lib/i18n.ts
export const translations = {
  hindi: {
    dashboard: {
      greeting: 'नमस्ते',
      startMonitoring: 'निगरानी शुरू करें',
      emergencyHelp: 'आपातकालीन सहायता',
      scamDetected: 'घोटाला पकड़ा गया!',
      endCall: 'कॉल समाप्त करें'
    },
    scamTypes: {
      digital_arrest: 'डिजिटल गिरफ्तारी घोटाला',
      parcel_scam: 'पार्सल घोटाला'
    }
  },
  malayalam: {
    dashboard: {
      greeting: 'നമസ്കാരം',
      startMonitoring: 'നിരീക്ഷണം ആരംഭിക്കുക',
      emergencyHelp: 'അടിയന്തര സഹായം',
      scamDetected: 'തട്ടിപ്പ് കണ്ടെത്തി!',
      endCall: 'കോൾ അവസാനിപ്പിക്കുക'
    },
    scamTypes: {
      digital_arrest: 'ഡിജിറ്റൽ അറസ്റ്റ് തട്ടിപ്പ്',
      parcel_scam: 'പാഴ്സൽ തട്ടിപ്പ്'
    }
  },
  english: {
    dashboard: {
      greeting: 'Hello',
      startMonitoring: 'Start Monitoring',
      emergencyHelp: 'Emergency Help',
      scamDetected: 'Scam Detected!',
      endCall: 'End Call'
    },
    scamTypes: {
      digital_arrest: 'Digital Arrest Scam',
      parcel_scam: 'Parcel Scam'
    }
  }
};
```

## 9. Error Handling and Monitoring

### 9.1 Error Handling Strategy
- Graceful degradation for API failures
- User-friendly error messages in selected language
- Automatic retry with exponential backoff
- Fallback to offline mode when needed

### 9.2 Monitoring and Logging
- Supabase dashboard for database metrics
- Azure Monitor for Speech API performance
- AWS CloudWatch for Bedrock usage
- Twilio dashboard for SMS delivery rates
- Custom logging for scam detection accuracy

### 9.3 Alert System
- Email alerts for system errors
- SMS alerts for critical failures
- Dashboard for real-time monitoring
- Weekly performance reports

## 10. Deployment Architecture

### 10.1 Hosting
- Frontend: Vercel (Next.js with edge functions)
- Database: Supabase (PostgreSQL + Realtime)
- CDN: Vercel Edge Network for global performance

### 10.2 Environment Variables
```
# Supabase
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Azure Speech Services
AZURE_SPEECH_KEY=
AZURE_SPEECH_REGION=

# Amazon Bedrock
AWS_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Twilio
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=

# App Configuration
NEXT_PUBLIC_APP_URL=
```

### 10.3 CI/CD Pipeline
- GitHub Actions for automated testing
- Vercel for automatic deployments on push
- Database migrations via Supabase CLI
- Staging environment for testing

## 11. Testing Strategy

### 11.1 Unit Tests
- API route handlers
- Scam detection algorithms
- Utility functions (language detection, formatting)

### 11.2 Integration Tests
- Azure Speech-to-Text integration
- Amazon Bedrock API integration
- Twilio SMS delivery
- Supabase Realtime subscriptions

### 11.3 End-to-End Tests
- Complete user flow: Audio capture → Transcription → Analysis → Alert
- Family notification flow
- Offline mode functionality
- Multi-language support

### 11.4 User Acceptance Testing
- Test with actual senior citizens
- Validate UI readability and usability
- Test with real scam call recordings (Hindi/Malayalam)
- Measure detection accuracy (target: 85%+)

## 12. Future Enhancements

### 12.1 Phase 2 Features
- Voice biometrics to detect caller identity
- Integration with India's National Cybercrime Portal
- Community scam reporting and alerts
- AI-powered scam prediction (before call starts)

### 12.2 Platform Expansion
- iOS and Android native apps
- WhatsApp bot for alerts
- Browser extension for web calls
- Smart speaker integration (Alexa, Google Home)

### 12.3 Advanced Analytics
- Regional scam trend analysis
- Scammer phone number database
- Predictive alerts based on call patterns
- Integration with telecom providers for call blocking

