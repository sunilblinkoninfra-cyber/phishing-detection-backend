import requests

def quarantine_message(token: str, message_id: str):
    requests.post(
        f"https://graph.microsoft.com/v1.0/users/me/messages/{message_id}/move",
        headers={"Authorization": f"Bearer {token}"},
        json={"destinationId": "quarantine"}
    )
