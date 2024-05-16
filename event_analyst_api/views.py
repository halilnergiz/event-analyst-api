from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import update_session_auth_hash
from django.urls import reverse
from django.conf import settings
from django.contrib.auth import authenticate

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token
from rest_framework.decorators import permission_classes
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.parsers import MultiPartParser, FormParser

import jwt

from .serializers import (
    UserSerializer,
    EmailVerificationSerializer,
    ChangePasswordSerializer,
    EventSerializer,
    PhotoSerializer,
)
from .models import CustomUser, Event, Photo
from .utils import Util


# USER VIEWS


@api_view(["GET"])
def get_user_info(request, email):
    try:
        user = CustomUser.objects.get(email=email)
        return Response(
            {
                "username": user.username,
                "email": user.email,
                "is_verified": user.is_verified,
            }
        )
    except CustomUser.DoesNotExist:
        return Response({"error: User not found!"}, status=status.HTTP_404_NOT_FOUND)


@api_view(["POST"])
def register_user(request):
    if request.method == "POST":
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = CustomUser.objects.get(email=user_data["email"])

            token = RefreshToken.for_user(user).access_token

            current_site = get_current_site(request).domain
            relativeLinks = reverse("email_verify")
            absurl = "http://" + current_site + relativeLinks + "?token=" + str(token)
            email_body = (
                "Hi "
                + user.username
                + " Use link below to verify your email\n"
                + absurl
            )
            data = {
                "email_body": email_body,
                "to_email": user.email,
                "email_subject": "Verify your email",
            }

            Util.send_email(data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def user_login(request):
    if request.method == "POST":
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)

        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)

        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == "POST":
        try:
            request.user.auth_token.delete()
            return Response(
                {"message": "Successfully logged out."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    if request.method == "POST":
        serializer = ChangePasswordSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data.get("new_password"))
            user.save()
            update_session_auth_hash(request, user)
            return Response(
                {"message": "Password changed successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# TODO
# @api_view(["GET"])
# def verify_email()
class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get("token")
        print(token)
        try:
            print("\ntrying somethin\n")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
            user = CustomUser.objects.get(id=payload["user_id"])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response(
                {"email": "Successfully activated"}, status=status.HTTP_201_CREATED
            )
        except jwt.ExpiredSignatureError as identifier:
            return Response(
                {"error": "Activation expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.exceptions.DecodeError as identifier:
            return Response(
                {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendActivationEmail(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.is_verified:
            return Response(
                {"detail": "Kullanıcı zaten aktif."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLinks = reverse("email_verify")
            absurl = "http://" + current_site + relativeLinks + "?token=" + str(token)
            email_body = (
                "Hi "
                + user.username
                + " Use link below to verify your email\n"
                + absurl
            )
            data = {
                "email_body": email_body,
                "to_email": user.email,
                "email_subject": "Verify your email",
            }

            Util.send_email(data)
            return Response(
                {"detail": "Resend activation mail, please check your mail"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            print(e)
            return Response(
                {"detail": "Activation mail couldn't send"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# EVENT VIEWS


@api_view(["POST"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def create_event(request):
    if request.method == "POST":
        serializer = EventSerializer(data=request.data, context={"request": request})
        print(serializer)
        if serializer.is_valid():
            event = serializer.save()
            response_serializer = EventSerializer(event)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def get_all_events(request):
    user_events = Event.objects.filter(event_owner=request.user)
    serializer = EventSerializer(user_events, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["DELETE"])
def delete_event(request, event_id):
    if request.method == "DELETE":
        try:
            event = Event.objects.get(eventId=event_id)
        except Event.DoesNotExist:
            return Response(
                {"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND
            )

        if event.event_owner != request.user:
            return Response(
                {"error": "You don't have permission to delete this event"},
                status=status.HTTP_403_FORBIDDEN,
            )

        event.delete()
        return Response(
            {"message": "Event deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )


@api_view(["PUT"])  # event_title necessary
def update_event(request, event_id):
    try:
        event = Event.objects.get(eventId=event_id, event_owner=request.user)
    except Event.DoesNotExist:
        return Response({"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = EventSerializer(event, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["PATCH"])
def partial_update_event(request, event_id):
    try:
        event = Event.objects.get(eventId=event_id, event_owner=request.user)
    except Event.DoesNotExist:
        return Response({"error": "Event not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = EventSerializer(event, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# PHOTO VIEWS


class PhotoCreateAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        photos_data = request.FILES.getlist("path")
        event_id = request.data.get("event")
        event = Event.objects.filter(eventId=event_id, event_owner=request.user).first()

        if event is None:
            return Response(
                {"detail": "Event does not exist"},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializers = [
            PhotoSerializer(data={"event": event_id, "path": photo})
            for photo in photos_data
        ]

        for serializer in serializers:
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        photo_instances = [
            Photo(event=event, path=serializer.validated_data["path"])
            for serializer in serializers
        ]
        Photo.objects.bulk_create(photo_instances)

        response_serializer = PhotoSerializer(photo_instances, many=True)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class PhotoDetailAPIView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Photo.objects.all()
    serializer_class = PhotoSerializer
    lookup_field = "photoId"


class EventPhotosListAPIView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PhotoSerializer

    def get_queryset(self):
        event_id = self.kwargs["eventId"]
        event = Event.objects.filter(
            eventId=event_id, event_owner=self.request.user
        ).first()
        if event:
            return Photo.objects.filter(event=event)
        else:
            return Photo.objects.none()

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if (
            not queryset.exists()
            and not Event.objects.filter(
                eventId=self.kwargs["eventId"], event_owner=self.request.user
            ).exists()
        ):
            return Response(
                {"detail": "Event does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class PhotoDeleteAPIView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Photo.objects.all()
    serializer_class = PhotoSerializer
    lookup_field = "photoId"

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.event.event_owner == request.user:
            self.perform_destroy(instance)
            return Response(
                {"detail": "Photo has been deleted successfully"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "You do not have permission to delete this photo."},
                status=status.HTTP_403_FORBIDDEN,
            )
