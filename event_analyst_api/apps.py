from django.apps import AppConfig


class EventAnalystApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "event_analyst_api"

    def ready(self):
        import event_analyst_api.signals
