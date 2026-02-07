# n8n Official MCP Client Guide

This guide explains how to connect the official n8n **MCP Client** node to this server using the Standard SSE (Server-Sent Events) transport.

## Prerequisites

1.  **n8n version**: Ensure you are using n8n v1.76.0 or later (which introduced the MCP Client node).
2.  **Server running**: Start this server in HTTP mode:
    ```bash
    npm run start:http
    ```
3.  **Auth Token**: Have your `AUTH_TOKEN` ready.

## Configuration in n8n

### Step 1: Add MCP Client Node
1.  Open your n8n workflow.
2.  Search for and add the **MCP Client** node.

### Step 2: Configure Credentials
1.  In the MCP Client node, click on **Credential to connect with**.
2.  Create a new **Header Auth** credential:
    -   **Name**: `Authorization`
    -   **Value**: `Bearer YOUR_AUTH_TOKEN_HERE` (replace with your actual token).

### Step 3: Node Parameters
1.  **Server Transport**: Select `Standard (SSE)`.
2.  **MCP Endpoint URL**: Enter the URL where your server is running, followed by `/mcp`.
    -   Example: `http://localhost:3000/mcp`
3.  **Authentication**: Select the Header Auth credential you created in Step 2.

### Step 4: Use Tools
1.  Click **Fetch Tools** (or wait for the list to populate).
2.  Select the **Tool** you want to execute (e.g., `search_nodes`).
3.  Configure the arguments in **Manual** or **JSON** mode.

## Why use Standard (SSE)?

While this server also supports the `HTTP Streamable` transport, the `Standard (SSE)` transport is the official protocol standard implemented by most MCP clients and is the most reliable way to connect to n8n's native MCP Client node.

## Troubleshooting

-   **Connection Refused**: Ensure the server is running and accessible from the n8n instance.
-   **Unauthorized**: Verify that your `Authorization` header is formatted correctly as `Bearer <token>`.
-   **Timeout**: If fetching tools takes too long, check the server logs for any database initialization delays.
