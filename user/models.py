from codecs import unicode_escape_decode
from enum import unique
from re import T
from django.db import models
from django.utils import timezone
from user.calculations import cal
from datetime import date
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
# Create your models here.


class MyUserManager(BaseUserManager):
    def create_user(self, email,firstname,lastname,dob,phone, address, password=None, password2=None):
        if not email:
            raise ValueError('Users must have an email address')
        
        if dob.year>date.today().year:
            raise ValueError('Invalid DOB')

        user = self.model(
            email=self.normalize_email(email),
            address=address,
            firstname=firstname,
            lastname=lastname,
            dob=dob,
            phone=phone,
        )

#save password + hashing
        user.set_password(password)
        # logic for dob
        dob = user.dob
        age = cal(dob)
        user.age = age
        user.address = address
        user.firstname= firstname
        user.lastname = lastname
        user.phone = phone
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(
            email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    email = models.EmailField( verbose_name='email', max_length=200, unique=True,)
    firstname = models.CharField(max_length=200)
    lastname = models.CharField(max_length=200)
    dob = models.DateField(null=True)
    age = models.IntegerField(null=True)
    phone = PhoneNumberField(null=True, unique=True)
    address = models.CharField(max_length=200, null=True)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS: list['firstname','lastname','dob','phone','address']
    REQUIRED_FIELDS = ['firstname','lastname','dob','phone','address']


    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for (key, value) in validated_data.items():
            setattr(instance, key, value)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class otp(models.Model):
    otp = models.IntegerField()
    otptype = models.CharField(max_length=200)
    valid = models.BooleanField(default=True)
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)
    # created_at = models.DateField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    
    




