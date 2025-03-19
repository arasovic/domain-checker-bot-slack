# Domain Checker Bot for Slack

This application checks how many days remain until specified domain names expire and sends notifications to a Slack channel.

## Features

- Automatically checks domain name expiration dates
- Sends Slack notifications for domains that will expire within a specified period (default 30 days)
- Can monitor multiple domains simultaneously
- Runs checks automatically with cron scheduling

## Installation

1. Clone or download the project:
   ```
   git clone https://github.com/arasovic/domain-checker-bot-slack.git
   cd domain-checker-bot-slack
   ```

2. Install required packages:
   ```
   npm install
   ```

3. Edit the `.env` file:
   - `DOMAINS` - List the domain names to check, separated by commas
   - `WARNING_DAYS` - Specify how many days before expiration you want to receive notifications
   - `SLACK_TOKEN` - Enter your Slack API token here
   - `SLACK_CHANNEL` - Enter the name of the Slack channel where notifications will be sent
   - `CRON_SCHEDULE` - Specify how frequently checks will run in cron format
   - `USE_RDAP` - Set to true to use RDAP protocol instead of WHOIS

4. Creating a Slack App:
   - Go to the [Slack API page](https://api.slack.com/apps)
   - Click the "Create an App" button
   - Choose "From scratch" option and set a name
   - Add these permissions from the OAuth & Permissions section:
     - `chat:write`
     - `chat:write.public`
   - Create a bot token and add it to your `.env` file

## Usage

To start the application:

```
npm start
```

or

```
node index.js
```

## Customization

- You can change the `WARNING_DAYS` value in the `.env` file to adjust when notifications start
- You can modify the cron schedule to adjust the frequency of checks
- You can edit the Slack message format in the `index.js` file
