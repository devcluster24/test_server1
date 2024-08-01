from django.contrib import admin
from apps.ad.models import (
                            NavbarLink, 
                            TrendingTag, 
                            Banner, 
                            AdModel, 
                            FooterLink
                            )


admin.site.register(NavbarLink)
admin.site.register(FooterLink)
admin.site.register(TrendingTag)
admin.site.register(Banner)
admin.site.register(AdModel)