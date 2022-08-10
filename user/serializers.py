from dataclasses import fields
import email
from unittest import mock
from user.models import MyUser, otp
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
# from django.contrib.auth.models import User


class OtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = otp
        fields=['otp','valid']



class UserRegistrationSerializer(serializers.ModelSerializer):
  # We are writing this becoz we need confirm password field in our Registratin Request
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = MyUser
        fields=['email', 'password', 'password2', 'address','firstname','dob','lastname', 'phone']
        extra_kwargs={
        'password':{'write_only':True}
        }

    # # Validating Password and Confirm Password while Registration
    # def validate(self, attrs):
    #     password = attrs.get('password')
    #     password2 = attrs.get('password2')
    #     if password != password2:
    #         raise serializers.ValidationError("Password and Confirm Password doesn't match")
    #     return super.validate(attrs)



    def create(self, data):
        return MyUser.objects.create_user(
            email=data.get("email"),
            address = data.get("address"),
            firstname=data.get("firstname"),
            lastname=data.get("lastname"),
            dob=data.get("dob"),
            phone = data.get("phone"),
            password=data.get("password")
        )
    # def save(self, *args, **kwargs):
    #     self.age = s# Put your logic here.
    #     super(UserRegistrationSerializer, self).save(*args, **kwargs)
class ChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs


# class ChangePasswordSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
#     password2 = serializers.CharField(write_only=True, required=True)
#     old_password = serializers.CharField(write_only=True, required=True)

#     class Meta:
#         model = MyUser
#         fields = ('old_password', 'password', 'password2')

#     def validate(self, attrs):
#         if attrs['password'] != attrs['password2']:
#             raise serializers.ValidationError({"password": "Password fields didn't match."})

#         return attrs

#     def validate_old_password(self, value):
#         user = self.context.get('user')
#         if not user.check_password(value):
#             raise serializers.ValidationError({"old_password": "Old password is not correct"})
#         return value

#     def update(self, instance, validated_data):

#         instance.set_password(validated_data['password'])
#         instance.save()

#         return instance




class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = MyUser
        fields = ['email', 'password']




# class UserUpdateSerializer(serializers.ModelSerializer):
#     update = UserRegistrationSerializer()

#     def update(self, instance, validated_data):
#         """Override update method because we need to update
#         nested serializer for profile
#         """
#         if validated_data.get('profile'):
#             profile_data = validated_data.get('profile')
#             profile_serializer = UserRegistrationSerializer(data=profile_data)

#             if profile_serializer.is_valid():
#                 profile = profile_serializer.update(instance=instance.profile)
#                 validated_data['update'] = profile

#         return super(UserUpdateSerializer, self).update(instance, validated_data)

#     class Meta:
#         model = MyUser
#         fields=['email', 'address','firstname','dob','lastname', 'phone']


class UserUpdateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = MyUser
        fields=['address','firstname','dob','lastname', 'phone']

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # The default result (access/refresh tokens)
        data = super(CustomTokenObtainPairSerializer, self).validate(attrs)
        # Custom data you want to include
        data.update({'user': self.user.username})
        data.update({'id': self.user.id})
        # and everything else you want to send in the response
        return data

# class ForgotPasswordSerializer(serializers.ModelSerializer):
    
#     class Meta:
#         model = MyUser
#         fields=['email']


