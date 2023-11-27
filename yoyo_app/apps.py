from django.apps import AppConfig


class YoyoappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'yoyo_app'

    # def ready(self):
    #     import management.commands.create_users  # Import your signals module
