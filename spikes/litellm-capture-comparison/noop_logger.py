"""No-op CustomLogger for the overhead bench: every hook a Cerberus plugin
would implement fires, but does nothing. Isolates LiteLLM's hook dispatch
cost from the dump_logger's deliberately heavy file writes."""

from litellm.integrations.custom_logger import CustomLogger


class NoopLogger(CustomLogger):
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        kwargs.get("standard_logging_object")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        kwargs.get("standard_logging_object")

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        return data

    async def async_post_mcp_tool_call_hook(self, kwargs, response_obj, start_time, end_time):
        return None


handler = NoopLogger()
