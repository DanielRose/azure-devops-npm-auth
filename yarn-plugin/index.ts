import {
  Configuration,
  SettingsType,
  Ident,
  StreamReport,
} from "@yarnpkg/core";
import type { Hooks, Plugin } from "@yarnpkg/core";
import type { Hooks as NpmHooks } from "@yarnpkg/plugin-npm";
import * as chalk from "chalk";
import AsyncLock = require("async-lock");
import { custom } from "openid-client";
import type { Client, Issuer, TokenSet } from "openid-client";

import { MsoIssuer, MsoDeviceCodeClientMedata } from "../authentication";
import { UserYarnConfig } from "../yarn-config";

declare module "@yarnpkg/core" {
  interface ConfigurationValueMap {
    azDevOpsAuthClientId: string | null;
    azDevOpsAuthTenantId: string | null;
  }
}

interface RequestInfo {
  configuration: Configuration;
  ident?: Ident;
}

// IDs found in:
// - https://github.com/microsoft/artifacts-credprovider/blob/master/src/Authentication/MsalConstants.cs
// - https://github.com/microsoft/artifacts-credprovider/blob/master/src/Authentication/AzureArtifacts.cs

const AZDEVOPS_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798";

// Azure Artifacts application ID
const AZDEVOPS_AUTH_CLIENT_ID = "d5a56ea4-7369-46b8-a538-c370805301bf"; // alternatively use "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", which is the Visual Studio application id

const AZDEVOPS_AUTH_TENANT_ID = "common";

const lock = new AsyncLock();
const authTokenMap = new Map<string, TokenSet>();

function log(requestInfo: RequestInfo, text: string): void {
  StreamReport.start(
    { configuration: requestInfo.configuration, stdout: process.stdout },
    async (report) => {
      const prefixedText = requestInfo.ident
        ? `${chalk.hex("#87afff")("[azure-devops-auth]")} ${
            requestInfo.ident.scope
              ? chalk.hex("#d75f00")(`@${requestInfo.ident.scope}/`)
              : ""
          }${chalk.hex("#d7875f")(requestInfo.ident.name)} ${text}`
        : text;
      report.reportInfo(null, prefixedText);
    }
  ).then();
}

const plugin: Plugin<Hooks & NpmHooks> = {
  configuration: {
    azDevOpsAuthClientId: {
      description: `The client-id to use for connecting to the authentication provider`,
      type: SettingsType.STRING,
      default: null,
    },
    azDevOpsAuthTenantId: {
      description: `The tenant-id to use for connecting to the authentication provider`,
      type: SettingsType.STRING,
      default: null,
    },
  },
  hooks: {
    async getNpmAuthenticationHeader(
      _currentHeader: string | undefined,
      registry: string,
      requestInfo: RequestInfo
    ): Promise<string | undefined> {
      if (
        !registry.startsWith("https://pkgs.dev.azure.com") &&
        !registry.startsWith("http://pkgs.dev.azure.com")
      ) {
        // Not getting a package from Azure DevOps, so we can skip
        return undefined;
      }

      if (process.env.SYSTEM_ACCESSTOKEN) {
        // Use the security token of the CI environment
        return `Bearer ${process.env.SYSTEM_ACCESSTOKEN}`;
      }

      if (requestInfo.configuration.isCI) {
        log(requestInfo, "Skipped auth due to running in CI environment");
        return undefined;
      }

      const savedToken = authTokenMap.get(registry);
      if (savedToken && !savedToken.expired()) {
        // We have an auth-token, which is not expired, so we can use it.
        return `Bearer ${savedToken.access_token}`;
      }

      // Fetch requests for packages are done in parallel.
      // However, if the refresh-token is missing/invalid,
      // a new device code flow will be entered in parallel
      // for each package.
      //
      // Instead, we will handle the authentication in serial.
      // That way, once the first request was handled by the
      // user authenticating the device code flow, all other
      // requests will see and use the refresh-token.
      //
      // Improvements could be:
      // - Only enter the lock when the refresh-token is
      //   missing/invalid. However in that case, once we
      //   acquired the lock, we then need to recheck if
      //   a valid refresh-token was saved in the meantime.

      return await lock.acquire("azDevOps", async () => {
        const clientId =
          requestInfo.configuration.get("azDevOpsAuthClientId") ??
          AZDEVOPS_AUTH_CLIENT_ID;
        const tenantId =
          requestInfo.configuration.get("azDevOpsAuthTenantId") ??
          AZDEVOPS_AUTH_TENANT_ID;

        const userConfig = new UserYarnConfig();

        const issuer: Issuer<Client> = await MsoIssuer.discover(tenantId);
        const client = new issuer.Client(
          new MsoDeviceCodeClientMedata(clientId)
        );

        // Set timeout to 5s to workaround issue #18
        // https://github.com/gsoft-inc/azure-devops-npm-auth/issues/18
        client[custom.http_options] = function (options) {
          options.timeout = 5000;
          return options;
        };

        let tokenSet: TokenSet | undefined;
        const refreshToken = userConfig.getRegistryRefreshToken(registry);
        if (refreshToken) {
          try {
            log(requestInfo, "Trying to use refresh token...");

            tokenSet = await client.refresh(refreshToken);
          } catch (exception) {
            switch (exception.error) {
              case "invalid_grant":
                log(
                  requestInfo,
                  chalk.yellow("Refresh token is invalid or expired.")
                );
                break;
              case "interaction_required":
                log(requestInfo, chalk.yellow("Interaction required."));
                break;
              default:
                throw exception;
            }
          }
        }

        if (!tokenSet) {
          try {
            tokenSet = await startDeviceCodeFlow(client, requestInfo);
          } catch (error) {
            log(
              requestInfo,
              chalk.red(
                `Failure during OAuth with tenant-id ${tenantId} and client-id ${clientId}`
              )
            );

            throw error;
          }
        }

        // Save refresh-token to user's npm config
        userConfig.setRegistryRefreshToken(registry, tokenSet.refresh_token);

        // Save token to internal Map for later reuse
        authTokenMap.set(registry, tokenSet);

        return `Bearer ${tokenSet.access_token}`;
      });
    },
  },
};

export default plugin;

async function startDeviceCodeFlow(
  client: Client,
  requestInfo: RequestInfo
): Promise<TokenSet> {
  // Make sure to include 'offline_access' scope to receive refresh token.
  const handle = await client.deviceAuthorization({
    scope: `${AZDEVOPS_RESOURCE_ID}/.default offline_access`,
  });

  log(
    requestInfo,
    `To sign in, use a web browser to open the page ${handle.verification_uri} and enter the code ${handle.user_code} to authenticate.`
  );
  return await handle.poll();
}
