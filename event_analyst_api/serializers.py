from rest_framework import serializers
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["username", "email", "password"]
        extra_kwargs = {"password": {"write_only": True}}

        def get_user_info(email):
            user = CustomUser.objects.filter(email=email)
            if user.exists():
                user = user.get()
                serializer = UserSerializer(user)
                return serializer.data
            else:
                return None

        def create(self, validated_data):
            user = CustomUser(
                username=validated_data["username"], email=validated_data["email"]
            )
            user.set_password(validated_data["password"])
            user.save()
            return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = CustomUser
        fields = ["token"]
