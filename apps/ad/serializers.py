from rest_framework import serializers
from apps.ad.models import (
                            NavbarLink, 
                            TrendingTag, 
                            Banner, 
                            AdModel, 
                            FooterLink,
                            Logo,
                            CompanyBanner
                            )


class NavbarLinkSerializers(serializers.ModelSerializer):
    class Meta:
        model = NavbarLink
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = '__all__'


class TrendingTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrendingTag
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = '__all__'


class BannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Banner
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = [
                  'id', 'page', 'image', 
                  'link', 'height', 'width', 
                  'order', 'created_at', 'updated_at'
                  ]
        

class AdSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdModel
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = [
                  'id', 'page', 'section', 'file_type', 
                  'image', 'link', 'video', 
                  'height', 'width', 'order',
                  'created_at', 'updated_at'
                  ]
        

class FooterLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = FooterLink
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = [
                  'id', 'name', 'url', 
                  'column', 'order',
                  'created_at', 'updated_at'
                  ]


class LogoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Logo
        fields = '__all__'


class CompanyBannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyBanner
        fields = '__all__'