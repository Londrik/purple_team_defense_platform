# MITRE ATT&CK v14+ Mapping & ECS 8.x Schemas

## 1. Attack Vector Correlation Matrix

| Attack Vector (OWASP Juice Shop) | MITRE ATT&CK Tactic | MITRE ATT&CK Technique | Containment Policy |
|---|---|---|---|
| SQL Injection (SQLi) | `TA0001` — Initial Access | `T1190` — Exploit Public-Facing Application | Immediate source IP drop in `PURPLE_JAIL` |
| Path Traversal / LFI | `TA0007` — Discovery | `T1083` — File and Directory Discovery | Immediate source IP drop in `PURPLE_JAIL` |
| Cross-Site Scripting (Reflected XSS) | `TA0001` — Initial Access | `T1189` — Drive-by Compromise | Alert and threshold/rate-based containment |
| Broken Object Level Authorization (BOLA/IDOR) | `TA0004` — Privilege Escalation | `T1068` — Exploitation for Privilege Escalation | Immediate source IP drop in `PURPLE_JAIL` |

## 2. Canonical ECS 8.x Normalized Event Schemas

### SQL Injection (`TA0001` / `T1190`)

~~~json
{
  "@timestamp": "2026-11-20T18:00:00.000Z",
  "event": {
    "kind": "alert",
    "category": "intrusion_detection",
    "type": "denied",
    "module": "juice_shop_purple_team"
  },
  "source": {
    "ip": "203.0.113.45"
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "url": {
    "path": "/rest/products/search"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0001",
      "name": "Initial Access"
    },
    "technique": {
      "id": "T1190",
      "name": "Exploit Public-Facing Application"
    }
  }
}
~~~

### Path Traversal / LFI (`TA0007` / `T1083`)

~~~json
{
  "@timestamp": "2026-11-20T18:01:00.000Z",
  "event": {
    "kind": "alert",
    "category": "intrusion_detection",
    "type": "denied",
    "module": "juice_shop_purple_team"
  },
  "source": {
    "ip": "203.0.113.45"
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "url": {
    "path": "/ftp/..%2F..%2Fetc%2Fpasswd"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0007",
      "name": "Discovery"
    },
    "technique": {
      "id": "T1083",
      "name": "File and Directory Discovery"
    }
  }
}
~~~

### Reflected XSS (`TA0001` / `T1189`)

~~~json
{
  "@timestamp": "2026-11-20T18:02:00.000Z",
  "event": {
    "kind": "alert",
    "category": "intrusion_detection",
    "type": "denied",
    "module": "juice_shop_purple_team"
  },
  "source": {
    "ip": "203.0.113.46"
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "url": {
    "path": "/rest/track-order/123"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0001",
      "name": "Initial Access"
    },
    "technique": {
      "id": "T1189",
      "name": "Drive-by Compromise"
    }
  }
}
~~~

### Broken Object Level Authorization — BOLA/IDOR (`TA0004` / `T1068`)

~~~json
{
  "@timestamp": "2026-11-20T18:03:00.000Z",
  "event": {
    "kind": "alert",
    "category": "intrusion_detection",
    "type": "denied",
    "module": "juice_shop_purple_team"
  },
  "source": {
    "ip": "203.0.113.47"
  },
  "http": {
    "request": {
      "method": "GET"
    }
  },
  "url": {
    "path": "/rest/basket/2"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "tactic": {
      "id": "TA0004",
      "name": "Privilege Escalation"
    },
    "technique": {
      "id": "T1068",
      "name": "Exploitation for Privilege Escalation"
    }
  }
}
~~~
