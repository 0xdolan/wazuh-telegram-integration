#!/var/ossec/venv/bin/python

import requests

bot_token = ""  # Replace with your bot token


def get_chat_id():
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if "result" in data and len(data["result"]) > 0:
            # Get chat ID from the last message
            chat_id = data["result"][-1]["message"]["chat"]["id"]
            print(f"Your Chat ID is: {chat_id}")
        else:
            print("No messages found. Please send a message to your bot first.")
    else:
        print(f"Failed to get updates: {response.status_code}")


if __name__ == "__main__":
    get_chat_id()
