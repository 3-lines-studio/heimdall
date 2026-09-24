use serde_json::json;

pub struct Mail {
    key: String,
    from: String,
}

impl Mail {
    pub fn from_env() -> Option<Mail> {
        let key = std::env::var("RESEND_API_KEY").ok()?;
        let from = std::env::var("HEIMDALL_FROM")
            .unwrap_or_else(|_| "Heimdall <heimdall@3lines.studio>".to_string());
        Some(Mail { key, from })
    }

    pub fn send_link(&self, to: &str, link: &str) -> std::result::Result<(), String> {
        let response = ureq::post("https://api.resend.com/emails")
            .set("Authorization", &format!("Bearer {}", self.key))
            .send_json(json!({
                "from": self.from,
                "to": [to],
                "subject": "Tu link para entrar a Heimdall",
                "html": body(link),
            }));
        match response {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(status, response)) => {
                let text = response.into_string().unwrap_or_default();
                Err(format!("resend contestó {status}: {text}"))
            }
            Err(e) => Err(format!("no pude mandar el mail: {e}")),
        }
    }
}

fn body(link: &str) -> String {
    format!(
        "<p>Entrá a Heimdall con este link:</p>\
         <p><a href=\"{link}\">{link}</a></p>\
         <p>Vence en quince minutos y sirve una sola vez.</p>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_carries_the_link() {
        assert!(body("https://x/auth?token=abc").contains(r#"href="https://x/auth?token=abc""#));
    }
}
