# API Reference

Reference for the sequencer REST API.

## Base URL

Default: `http://localhost:8080`

## Authentication

Currently no authentication required. In production, consider adding:
- API keys
- Rate limiting
- IP whitelisting

## Endpoints

### POST /submit

Submit a transaction to the mempool.

**Request Body:**

```json
{
  "proof": {
    "a": ["0x...", "0x..."],
    "b": [["0x...", "0x..."], ["0x...", "0x..."]],
    "c": ["0x...", "0x..."]
  },
  "anchor_info": "0x...",
  "nullifier0": "0x...",
  "nullifier1": "0x...",
  "leaf0": "0x...",
  "leaf1": "0x...",
  "leaf2": "0x..."
}
```

**Response (Success):**

```json
{
  "status": "accepted",
  "position": 150
}
```

**Response (Error):**

```json
{
  "status": "rejected",
  "reason": "NullifierAlreadySpent",
  "details": {
    "nullifier": "0x...",
    "block_nr": 1234,
    "tx_index": 5
  }
}
```

**Error Reasons:**

| Reason | Description |
|--------|-------------|
| `MempoolFull` | Mempool at capacity |
| `NullifierAlreadySpent` | Nullifier used in confirmed block |
| `NullifierPending` | Nullifier in mempool queue |
| `DuplicateNullifiersInTx` | Same nullifier used twice |
| `AnchorBlockInFuture` | Reference to non-existent block |
| `AnchorUpdateOutOfBounds` | Update index too high |
| `AnchorNotFound` | Anchor not in database |
| `InvalidZkProof` | ZK proof verification failed |

---

### POST /poke

Force immediate block submission with current mempool contents.

**Request Body:** None

**Response:**

```json
{
  "status": "triggered"
}
```

**Notes:**
- Block will be submitted on next builder loop iteration
- May submit empty block if no transactions pending

---

### GET /stats

Get mempool statistics.

**Response:**

```json
{
  "pending": 150,
  "max_pending": 10000,
  "oldest_age_ms": 5000,
  "blobs_worth": 0,
  "pending_nullifiers": 300
}
```

**Fields:**

| Field | Description |
|-------|-------------|
| `pending` | Number of pending transactions |
| `max_pending` | Maximum allowed pending |
| `oldest_age_ms` | Age of oldest transaction in ms |
| `blobs_worth` | Number of full blobs in queue |
| `pending_nullifiers` | Number of tracked nullifiers |

---

### GET /health

Health check endpoint.

**Response (Healthy):**

```json
{
  "status": "healthy",
  "block_number": 1234,
  "epoch": 100,
  "is_closed": true
}
```

**Response (Unhealthy):**

```json
{
  "status": "unhealthy",
  "error": "RPC connection failed"
}
```

---

## WebSocket (Future)

Planned WebSocket API for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);

  switch (msg.type) {
    case 'block_submitted':
      console.log('New block:', msg.block_nr);
      break;
    case 'tx_included':
      console.log('Transaction included:', msg.nullifiers);
      break;
  }
};
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (invalid input) |
| 422 | Validation failed |
| 429 | Rate limited |
| 500 | Internal server error |
| 503 | Service unavailable |

### Error Response Format

```json
{
  "status": "error",
  "code": "VALIDATION_FAILED",
  "message": "Human readable message",
  "details": {
    // Error-specific details
  }
}
```

---

## Rate Limiting

Recommended limits for production:

| Endpoint | Limit |
|----------|-------|
| POST /submit | 100/min per IP |
| POST /poke | 10/min per IP |
| GET /stats | 60/min per IP |
| GET /health | 120/min per IP |

---

## Usage Examples

### Submit Transaction (curl)

```bash
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/json" \
  -d '{
    "proof": {
      "a": ["0x123...", "0x456..."],
      "b": [["0x789...", "0xabc..."], ["0xdef...", "0x012..."]],
      "c": ["0x345...", "0x678..."]
    },
    "anchor_info": "0x...",
    "nullifier0": "0x...",
    "nullifier1": "0x...",
    "leaf0": "0x...",
    "leaf1": "0x...",
    "leaf2": "0x..."
  }'
```

### Submit Transaction (JavaScript)

```javascript
const response = await fetch('http://localhost:8080/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    proof: { a: [...], b: [...], c: [...] },
    anchor_info: '0x...',
    nullifier0: '0x...',
    nullifier1: '0x...',
    leaf0: '0x...',
    leaf1: '0x...',
    leaf2: '0x...'
  })
});

const result = await response.json();
if (result.status === 'accepted') {
  console.log('Transaction accepted at position', result.position);
}
```

### Submit Transaction (Rust)

```rust
use reqwest::Client;

let client = Client::new();
let response = client
    .post("http://localhost:8080/submit")
    .json(&transaction)
    .send()
    .await?;

let result: SubmitResponse = response.json().await?;
```

### Monitor Stats (Python)

```python
import requests
import time

while True:
    response = requests.get('http://localhost:8080/stats')
    stats = response.json()

    print(f"Pending: {stats['pending']}")
    print(f"Blobs worth: {stats['blobs_worth']}")

    time.sleep(5)
```

---

## SDK (Future)

Planned SDK for common languages:

```typescript
// TypeScript SDK example
import { PGPClient } from '@pgp/sdk';

const client = new PGPClient('http://localhost:8080');

// Submit transaction
const result = await client.submit(transaction);

// Get stats
const stats = await client.getStats();

// Subscribe to events
client.on('blockSubmitted', (block) => {
  console.log('New block:', block.blockNr);
});
```
