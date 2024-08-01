from rest_framework import serializers
from apps.news.models import (
                              Category, 
                              SearchFilter, 
                              Location, 
                              NewsPost,
                              FilterNews,
                              Division,
                              District, 
                              Upazila
                              )


class CategorySerializers(serializers.ModelSerializer):
    class Meta:
        model = Category
        extra_kwargs = {
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        }
        fields = [
                 'id', 'name', 'description', 'order',
                 'created_at', 'updated_at'
                 ]


class DivisionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Division
        fields = '__all__'


class DistrictSerializer(serializers.ModelSerializer):
    class Meta:
        model = District
        fields = '__all__'


class UpazilaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Upazila
        fields = '__all__'


class FilterNewsSerializers(serializers.ModelSerializer):
    class Meta:
        model = FilterNews
        extra_kwargs = {
                        'division': {'required': False}, 
                        'district': {'required': False}, 
                        'upazila': {'required': False}
                        }
        fields = [
                  'division', 'district', 
                  'upazila'
                  ]


class SearchFilterSerializers(serializers.ModelSerializer):
    class Meta:
        model = SearchFilter
        fields = ['division', 'district', 'upazila', 'category']


class LocationSerializers(serializers.ModelSerializer):
    class Meta:
        model = Location
        extra_kwargs = {
                        'division': {'required': False}, 
                        'district': {'required': False},
                        'upazila': {'required': False},
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        'custom_location': {'required': False},
                        }
        fields = [
                  'id', 'location_type', 
                  'division', 'district',
                  'upazila', 'custom_location',
                  'created_at', 'updated_at'
                  ]
    

class NewsPostSerializers(serializers.ModelSerializer):
    category_name = serializers.SerializerMethodField()
    editor_name = serializers.SerializerMethodField()
    custom_location = serializers.SerializerMethodField()
    division = serializers.SerializerMethodField()
    district = serializers.SerializerMethodField()
    upazila = serializers.SerializerMethodField()

    class Meta:
        model = NewsPost
        extra_kwargs = {
                        'trending_tags': {'required': False}, 
                        'share_count': {'required': False}, 
                        'created_at': {'required': False},
                        'updated_at': {'required': False},
                        'editor': {'required': False},
                        'is_active': {'required': False}
                        }
        fields = ['id', 'headline', 'content', 
                  'category', 'category_name', 'editor', 
                  'editor_name', 'is_active', 'custom_location',
                  'location', 'division', 'district', 'upazila',
                  'trending_tags', 'image', 'video', "share_count",
                  'photo_editor', 'created_at', 'updated_at'
                  ]
    
    def get_category_name(self, obj):
        return obj.category.name
    
    def get_editor_name(self, obj):
        return obj.editor.username
    
    def get_custom_location(self, obj):
        return obj.location.custom_location
    
    def get_division(self, obj):
        return obj.location.division
    
    def get_district(self, obj):
        return obj.location.district
    
    def get_upazila(self, obj):
        return obj.location.upazila