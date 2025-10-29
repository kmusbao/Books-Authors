from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import User, Book


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('password', 'password2', 'first_name', 'last_name', 'email', 'is_active', 'is_staff', 'is_superuser')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data.pop('password2')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})
        return attrs


class LoginSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ('username', 'password')

class UserDetailsSerializer(UserSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password], required=False)
    password2 = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'username', 'password', 'password2', 'is_active', 'type',)
        read_only_fields = ('id',)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
            instance.save()
        return super().update(instance, validated_data)

    def validate(self, attrs):
        if 'password' and 'password2' in attrs:
            super().validate(attrs)
        elif 'password' in attrs and 'password2' not in attrs:
            raise serializers.ValidationError({'password2': 'This field is required.'})
        elif 'password2' in attrs and 'password' not in attrs:
            raise serializers.ValidationError({'password': 'This field is required.'})
        return attrs


class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = ('title', 'author', 'created_at')
