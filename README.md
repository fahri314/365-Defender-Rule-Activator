# 365 Defender Rule Activator

This script tests the custom rules that you add to the Microsoft 365 Defender product, and it activates those rules that do not produce results. It provides a list for you to review and edit the rules that produce results. If you want to check enabled rules too, disable all rules in the `Custom detection rules` page. The algorithmic working structure and example request-response data can be found in the `workflow.md` file.

## Config File

Before running the script, you must modify the values in the config file. You can obtain this data from the network section of your browser while logged in to the session at the address below.

<https://security.microsoft.com/v2/advanced-hunting?tid=your_tenant_id>

### Step Count

If you have a problem during the execution of the script due to the wrong rules or too many requests, you can change the `step` value in the `config` file to continue from where you left off.
