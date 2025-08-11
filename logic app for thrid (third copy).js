{
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {
            "Microsoft_Sentinel_incident": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                        }
                    },
                    "body": {
                        "callback_url": "@listCallbackUrl()"
                    },
                    "path": "/incident-creation"
                }
            }
        },
        "actions": {
            "POST_to_Node": {
                "runAfter": {},
                "type": "Http",
                "inputs": {
                    "uri": "https://zq79bf2x-8000.inc1.devtunnels.ms/incident/activate",
                    "method": "POST",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "body": {
                        "incidentName": "@{triggerBody()?['object']?['name']}",
                        "correlationId": "@{workflow()?['run']?['name']}"
                    }
                },
                "runtimeConfiguration": {
                    "contentTransfer": {
                        "transferMode": "Chunked"
                    }
                }
            }
        },
        "outputs": {},
        "parameters": {
            "$connections": {
                "type": "Object",
                "defaultValue": {}
            }
        }
    },
    "parameters": {
        "$connections": {
            "type": "Object",
            "value": {
                "azuresentinel": {
                    "id": "/subscriptions/789ffe48-9506-43da-b629-b0b9174bad4d/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel",
                    "connectionId": "/subscriptions/789ffe48-9506-43da-b629-b0b9174bad4d/resourceGroups/SOCAutomationAgent/providers/Microsoft.Web/connections/azuresentinel",
                    "connectionName": "azuresentinel"
                }
            }
        }
    }
}