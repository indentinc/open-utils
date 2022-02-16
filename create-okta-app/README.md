# Create Okta Service App

A starter to create an Okta OAuth2.0 Service app via Okta's API.

### Requirements

- [Okta Account](https://okta.com)
- [Okta API Token](https://help.okta.com/en/prod/Content/Topics/Security/API.htm?cshid=Security_API#)
- [Node `v16+`](https://nodejs.org/dist/latest-v16.x/docs/api/)
- Optional: [Okta's guide to creating a Service App](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/overview/)

### Setup

Clone this repo:

```bash
git clone https://github.com/indent-testing/create-okta-app.git \
cd create-okta-app
```

Install the dependencies:

```bash
npm install
```

Build the Node file into a binary:

```bash
npm run build && npm link
```

### Usage

Make sure you have access to your Okta Domain URL and your Okta Admin API Token.

Use the app like this:

```bash
create-okta-app --domain dev-123456.okta.com --token 00asdfghjklqwertyuiop
```

These are the additional options:

```bash
--name okta_service_app # Rename your app
--keyid 789012 # Add a unique identifier for your JWK
--keysize 2048 # Increase the number of bits for your JWK
--scope okta.users.manage or okta.groups.manage # Used to manage users or groups
```
