
from django.contrib import admin
from user.models import MyUser
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserModelAdmin(BaseUserAdmin):
  # The fields to be used in displaying the User model.
  # These override the definitions on the base UserModelAdmin
  # that reference specific fields on auth.User.
  list_display = ( 'email','firstname','lastname', 'age', 'phone', 'address', 'dob', 'is_admin')
  list_filter = ('is_admin',)
  fieldsets = (
      ('User Credentials', {'fields': ('email', 'password')}),
      ('Personal info', {'fields': ('firstname','lastname', 'age', 'phone', 'address', 'dob')}),
      ('Permissions', {'fields': ('is_admin',)}),
  )
  # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
  # overrides get_fieldsets to use this attribute when creating a user.
#   add_fieldsets = (
#       (None, {
#           'classes': ('wide',),
#           'fields': ('email', 'password1', 'password2'),
#       }),
#   )
  search_fields = ('email',)
  ordering = ('email', 'id')
  filter_horizontal = ()


# Now register the new UserModelAdmin...
admin.site.register(MyUser, UserModelAdmin)
