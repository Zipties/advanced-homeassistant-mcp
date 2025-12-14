/**
 * Remote Control Tool for Home Assistant
 *
 * Control Android TV, Apple TV, Roku, and other remote-capable devices.
 * Supports turning on/off, sending commands, and launching activities (apps).
 */

import { z } from "zod";
import { logger } from "../../utils/logger.js";
import { get_hass } from "../../hass/index.js";
import { Tool } from "../../types/index.js";

// Service class for remote operations
class HomeAssistantRemoteService {
  async getRemotes(): Promise<Record<string, unknown>[]> {
    try {
      const hass = await get_hass();
      const states = await hass.getStates();
      return states
        .filter((state) => state.entity_id.startsWith("remote."))
        .map((state) => ({
          entity_id: state.entity_id,
          state: state.state,
          friendly_name: state.attributes?.friendly_name,
          supported_features: state.attributes?.supported_features,
          current_activity: state.attributes?.current_activity,
          activity_list: state.attributes?.activity_list,
        }));
    } catch (error) {
      logger.error("Failed to get remotes from HA:", error);
      return [];
    }
  }

  async getRemote(entity_id: string): Promise<Record<string, unknown> | null> {
    try {
      const hass = await get_hass();
      const state = await hass.getState(entity_id);
      return {
        entity_id: state.entity_id,
        state: state.state,
        attributes: state.attributes,
      };
    } catch (error) {
      logger.error(`Failed to get remote ${entity_id} from HA:`, error);
      return null;
    }
  }

  async callService(
    service: string,
    entity_id: string,
    data: Record<string, unknown> = {},
  ): Promise<boolean> {
    try {
      const hass = await get_hass();
      const serviceData = { entity_id, ...data };
      await hass.callService("remote", service, serviceData);
      return true;
    } catch (error) {
      logger.error(`Failed to call service ${service} on ${entity_id}:`, error);
      return false;
    }
  }
}

// Singleton instance
const haRemoteService = new HomeAssistantRemoteService();

// Schema for tool parameters
const remoteControlSchema = z.object({
  action: z
    .enum([
      "list",
      "get",
      "turn_on",
      "turn_off",
      "toggle",
      "send_command",
    ])
    .describe("The action to perform"),
  entity_id: z
    .string()
    .optional()
    .describe("The entity ID of the remote (required for most actions)"),
  activity: z
    .string()
    .optional()
    .describe("Activity/app to launch when turning on (e.g., 'com.plexapp.android' for Plex, 'com.netflix.ninja' for Netflix)"),
  command: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .describe("Command(s) to send (for send_command action)"),
  num_repeats: z
    .number()
    .optional()
    .describe("Number of times to repeat the command (default: 1)"),
  delay_secs: z
    .number()
    .optional()
    .describe("Delay between repeated commands in seconds (default: 0.4)"),
  hold_secs: z
    .number()
    .optional()
    .describe("How long to hold the command in seconds (default: 0)"),
});

type RemoteControlInput = z.infer<typeof remoteControlSchema>;

// Main execution function
async function execute(params: RemoteControlInput): Promise<string> {
  const {
    action,
    entity_id,
    activity,
    command,
    num_repeats,
    delay_secs,
    hold_secs,
  } = params;

  try {
    switch (action) {
      case "list": {
        const remotes = await haRemoteService.getRemotes();
        return JSON.stringify(
          {
            success: true,
            remotes,
            count: remotes.length,
          },
          null,
          2,
        );
      }

      case "get": {
        if (!entity_id) {
          return JSON.stringify({ success: false, error: "entity_id is required for get action" });
        }
        const remote = await haRemoteService.getRemote(entity_id);
        if (!remote) {
          return JSON.stringify({ success: false, error: `Remote ${entity_id} not found` });
        }
        return JSON.stringify({ success: true, remote }, null, 2);
      }

      case "turn_on": {
        if (!entity_id) {
          return JSON.stringify({
            success: false,
            error: "entity_id is required for turn_on action",
          });
        }
        const data: Record<string, unknown> = {};
        if (activity) {
          data.activity = activity;
        }
        const success = await haRemoteService.callService("turn_on", entity_id, data);
        const message = activity
          ? `Successfully turned on ${entity_id} with activity: ${activity}`
          : `Successfully turned on ${entity_id}`;
        return JSON.stringify({
          success,
          message: success ? message : `Failed to turn on ${entity_id}`,
        });
      }

      case "turn_off":
      case "toggle": {
        if (!entity_id) {
          return JSON.stringify({
            success: false,
            error: `entity_id is required for ${action} action`,
          });
        }
        const success = await haRemoteService.callService(action, entity_id);
        return JSON.stringify({
          success,
          message: success
            ? `Successfully executed ${action} on ${entity_id}`
            : `Failed to execute ${action} on ${entity_id}`,
        });
      }

      case "send_command": {
        if (!entity_id) {
          return JSON.stringify({
            success: false,
            error: "entity_id is required for send_command action",
          });
        }
        if (!command) {
          return JSON.stringify({
            success: false,
            error: "command is required for send_command action",
          });
        }
        const data: Record<string, unknown> = {
          command: Array.isArray(command) ? command : [command],
        };
        if (num_repeats !== undefined) data.num_repeats = num_repeats;
        if (delay_secs !== undefined) data.delay_secs = delay_secs;
        if (hold_secs !== undefined) data.hold_secs = hold_secs;

        const success = await haRemoteService.callService("send_command", entity_id, data);
        return JSON.stringify({
          success,
          message: success
            ? `Successfully sent command(s) to ${entity_id}`
            : `Failed to send command(s) to ${entity_id}`,
        });
      }

      default:
        return JSON.stringify({ success: false, error: `Unknown action: ${action}` });
    }
  } catch (error) {
    logger.error("Error in remote control tool:", error);
    return JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : "Unknown error occurred",
    });
  }
}

// Export the tool object
export const remoteControlTool: Tool = {
  name: "remote_control",
  description:
    "Control remote-capable devices in Home Assistant (Android TV, Apple TV, Roku, etc.). Supports turning on/off, launching activities (apps), and sending commands. Use turn_on with activity parameter to launch specific apps (e.g., 'com.plexapp.android' for Plex, 'com.netflix.ninja' for Netflix on Android TV).",
  annotations: {
    title: "Remote Control",
    description: "Control TV remotes, launch apps, send commands to Android TV, Apple TV, Roku, etc.",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  parameters: remoteControlSchema,
  execute,
};
