
from ast import Delete
import email
import datetime
from multiprocessing import context
from urllib import request
from django.shortcuts import render
from user.models import MyUser, otp
from user.serializers import UserRegistrationSerializer, UserLoginSerializer,UserUpdateSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status, generics
from django.contrib.auth import authenticate, logout
from rest_framework.viewsets import ViewSet, ModelViewSet
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated
from .serializers import CustomTokenObtainPairSerializer
import math, random
# from datetime import datetime, timedelta
from django.utils import timezone
# Create your views here.
import pytz

utc=pytz.UTC

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }




class UserRegistrationView(APIView):
    def post(self, request, format=None):
        if request.data.get("password")==request.data.get("password2"):
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                number = random.randint(1111,9999)
                email1 = request.data['email']  
                htmlgen = f'<p>Your OTP is <strong>{number}</strong></p>'
                # send_mail(subject, message, from_email, recipient_list, fail_silently=False, auth_user=None, auth_password=None, connection=None, html_message=None)
                send_mail('Otp for mail verification',str(number),'khushbu20patil@gmail.com',[email1,],fail_silently=False, html_message=htmlgen)
                current_user = MyUser.objects.get(email = email1)
                print("current user >>>>>", current_user)
                otp.objects.create(otp=int(number), user=current_user,otptype='register')
                return Response(data={'msg':'Registration Successful Now please Verify Your Email'},status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(data={"message":"password is differet"}, status=status.HTTP_400_BAD_REQUEST)

class Verifyotp(APIView):   
    def post(self, request):
    # type = "verification"
        email = request.data["email"]
        Userotp = request.data["otp"]
        
        try:
            user = MyUser.objects.get(email=email)
            if user.is_active == True:
                return Response("Email already registered")
            try:
                email_in_otp = otp.objects.get(user__email=user.email)
            except:
                return Response("Email not registered")
            otp_obj = otp.objects.get(user=user)
            dataotp = otp.objects.get(user=user).otp
            otp_created = otp_obj.created_at
            expire = otp_created + datetime.timedelta(days=1,)
            print(datetime.datetime.now(pytz.UTC), ">>>>>>>>", expire)
            if email == email_in_otp.user.email:
                if email_in_otp.otptype == "register":
                    if int(Userotp) == dataotp:
                        if datetime.datetime.now(pytz.UTC) < expire:
                            if Userotp==str(dataotp):
                                user.is_active = True
                                otp_obj.valid = False
                                # print("??????????????????????????????????????????????????????????")
                                otp_obj.delete()
                                user.save()
                                return Response("Verification Successful")
                            else:
                                return Response("OTP Verification failed")
                        else:
                            return Response("OTP is expire Please try again")
                    else:
                        return Response("Invalid OTP Please check your OTP")
                else:
                    return Response("Invalid Otp")
        except MyUser.DoesNotExist :
            return Response("Invalid email")

class OtpForFPView(APIView):
    def post(self, request):
        email = request.data["email"]
        try:
            email1 = MyUser.objects.get(email=email)
            if email1:
                number = random.randint(1111,9999)
                htmlgen = f'<p>Your OTP is <strong>{number}</strong></p>'
                # send_mail(subject, message, from_email, recipient_list, fail_silently=False, auth_user=None, auth_password=None, connection=None, html_message=None)
                send_mail('YoUr OtP iS HeRe',str(number),'khushbu20patil@gmail.com',[email1,],fail_silently=False, html_message=htmlgen)
                current_user = MyUser.objects.get(email = email1)
                print("current user >>>>>", current_user)
                otp.objects.create(otp=int(number), user=current_user,otptype='Forgot Password')
                return Response(data={'msg':'OTP Send Pleas Check Your Mail'},status=status.HTTP_201_CREATED)
        except MyUser.DoesNotExist :
            return Response("Invalid email")


class VerifyotpForFP(APIView):   
    def post(self, request):
    # type = "verification"
        email = request.data["email"]
        Userotp = request.data["otp"]
        
        try:
            user = MyUser.objects.get(email=email)
            if user.is_active == True:
                return Response("Email already registered")
            try:
                email_in_otp = otp.objects.get(user__email=user.email)
            except:
                return Response("Email not registered")
            otp_obj = otp.objects.get(user=user)
            dataotp = otp.objects.get(user=user).otp
            otp_created = otp_obj.created_at
            expire = otp_created + datetime.timedelta(days=1,)
            print(datetime.datetime.now(pytz.UTC), ">>>>>>>>", expire)
            if email == email_in_otp.user.email:
                if email_in_otp.otptype == "Forgot Password":
                    if int(Userotp) == dataotp:
                        if datetime.datetime.now(pytz.UTC) < expire:
                            if Userotp==str(dataotp):
                                user.is_active = True
                                otp_obj.valid = False
                                otp_obj.delete()
                                user.save()
                                return Response("Verification Successful")
                            else:
                                return Response("OTP Verification failed")
                        else:
                            return Response("OTP is expire Please try again")
                    else:
                        return Response("Invalid OTP Please check your OTP")
                else:
                    return Response("Invalid Otp")
        except MyUser.DoesNotExist :
            return Response("Invalid email")


class ResendOtpRegisterView(APIView):
    def post(self, request):
        try:
            email = request.data["email"]
            email1 = MyUser.objects.get(email=email)
            number = random.randint(1111,9999)
            current_user = MyUser.objects.get(email = email1)
            all_otp = otp.objects.filter(user__email=email)
            type = request.data["type"]
        except MyUser.DoesNotExist:
            return Response("No account found!")
        if type != "register":
            return Response("otp type is wrong")
        for i in all_otp:
            i.delete()
        if current_user.is_active:
            return Response({'message': 'account already verified'})
        htmlgen = f'<p>Your OTP is <strong>{number}</strong></p>'

        # send_mail(subject, message, from_email, recipient_list, fail_silently=False, auth_user=None, auth_password=None, connection=None, html_message=None)
        send_mail('YoUr OtP iS HeRe',str(number),'khushbu20patil@gmail.com',[email1,],fail_silently=False, html_message=htmlgen)
        
        print("current user >>>>>", current_user)
        otp.objects.create(otp=int(number), user=current_user,otptype='register')
        return Response(data={'msg':'OTP Send Pleas Check Your Mail'},status=status.HTTP_201_CREATED)



class ResendOtpPasswordView(APIView):
    def post(self, request):
        try:
            email = request.data["email"]
            email1 = MyUser.objects.get(email=email)
            number = random.randint(1111,9999)
            current_user = MyUser.objects.get(email = email1)
            all_otp = otp.objects.filter(user__email=email)
        except MyUser.DoesNotExist:
            return Response("No account found!")
        if type != "Forgot Password":
            return Response("otp type is wrong")
        for i in all_otp:
            i.delete()
        if current_user.is_active==False:
            return Response({'message': 'No account please register your email'})
        htmlgen = f'<p>Your OTP is <strong>{number}</strong></p>'

        # send_mail(subject, message, from_email, recipient_list, fail_silently=False, auth_user=None, auth_password=None, connection=None, html_message=None)
        send_mail('YoUr OtP iS HeRe',str(number),'khushbu20patil@gmail.com',[email1,],fail_silently=False, html_message=htmlgen)
        
        print("current user >>>>>", current_user)
        otp.objects.create(otp=int(number), user=current_user,otptype='Forgot Password')
        return Response(data={'msg':'OTP Send Pleas Check Your Mail'},status=status.HTTP_201_CREATED)




# def send_otp(request,otp, email):
#     #  otp=generateOTP()
#     htmlgen = '<p>Your OTP is <strong>o</strong></p>'
#     # send_mail(subject, message, from_email, recipient_list, fail_silently=False, auth_user=None, auth_password=None, connection=None, html_message=None)
#     # send_mail('OTP request',otp,'khushbu20patil@gmail.com',[email,], fail_silently=False, html_message=htmlgen)
#     send_mail('OTP request',otp,'khushbu20patil@gmail.com',[email,],html_message=htmlgen)

#     return Response({'message':'send otp'})





class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email,password = password)
        if user is not None:
            if MyUser.objects.get(email=request.data['email']).is_active:
                token = get_tokens_for_user(MyUser.objects.get(email=request.data['email']))
                return Response({'token':token, 'message':'Login Successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserLogoutView(APIView):
    # permission_classes = [IsAuthenticated,]
    def post(self,request):
        logout(request)
        return Response({'message':'Logout Successful'}, status=status.HTTP_404_NOT_FOUND)




class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    # def put(self, request, format=None):
    #     serializer = ChangePasswordSerializer(data=request.data, context={'user':request.user})
    #     # user = MyUser.objects.get(email=email)
    #     # if (user.check_password()):
    #     serializer.is_valid(raise_exception=True)
    #     # u = MyUser.objects.get(email=request.user)
    #     # u.set_password('password')
    #     # u.save()
    #     return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
    def put(self, request):
        user = MyUser.objects.get(id=request.user.id)
        if request.data['password'] != request.data['password2']:
            return Response({'error': 'password do not match!'})
        password = request.data['password']
        user.set_password(password)
        user.save()
        return Response({'message': "password succesfully changed"})


        # password = request.data["password"]
        # password1 = request.data["password"]
        # old_password = request.data["old_password"]
        # db_password = MyUser.objects.get(email=request.user).password
        # if db_password :
        #     print(db_password)
        #     if password == password1 :
        #         print(db_password,"<<<<<<<<<")
        #         user = UserUpdateSerializer(request.user, data=request.data)
        #         if user.is_valid():
        #             user.save()
        #             return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
        #     else:
        #         print(db_password,">>>>>>>>>>")
        #         return Response({'msg':'Password and password is different'}, status=status.HTTP_404_NOT_FOUND)
        # else:
        #     print(db_password,"/////////////")
            # return Response({'msg':'old password is wrong'}, status=status.HTTP_404_NOT_FOUND)
            # serializer = ChangePasswordSerializer(data=request.data, context={"user":request.user})
            # # if serializer.is_valid(raise_exception=True):
            #     return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)





class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated,]
    def put(self, request, format=None):
        user = UserUpdateSerializer(request.user, data=request.data)
        if user.is_valid():
            user.save()
        return Response({'msg':'You have updated your profile Details'},status=status.HTTP_200_OK)
        


class UserDeleteView(APIView):
    permission_classes = [IsAuthenticated,]
    def delete(self, request):
        user = MyUser.objects.get(email=request.user)
        if user:
            user.delete()
            return Response({'message':'Delete Successful'},status=status.HTTP_204_NO_CONTENT)
        return Response({"message":"user not found."})


from rest_framework_simplejwt.views import TokenObtainPairView

class CustomTokenObtainPairView(TokenObtainPairView):
    # Replace the serializer with your custom
    serializer_class = CustomTokenObtainPairSerializer
        
# def generateOTP() :
#      digits = "0123456789"
#      OTP = ""
#      for i in range(4) :
#          OTP += digits[math.floor(random.random() * 10)]
#      return OTP

        
# class UserRegistrationView(ViewSet):

#     def list(self, request):
#         courses = MyUser.objects.all()
#         serializer = UserRegistrationSerializer(courses, many=True)
#         return Response(serializer.data)

#     def create(self, request):
#         serializer = UserRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         return Response(serializer.errors)

#     def retrieve(self, request, pk):
#         try:
#             course = MyUser.objects.get(pk=pk)
#         except MyUser.DoesNotExist:
#             return Response(status=status.HTTP_404_NOT_FOUND)
#         serializer = UserRegistrationSerializer(course)
#         return Response(serializer.data)

