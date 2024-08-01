from rest_framework import status, generics, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from apps.news.pagination import NewsPostPagination
from apps.news.models import (
                              Category, 
                              Location, 
                              FilterNews, 
                              NewsPost,
                              Division,
                              District,
                              Upazila
                              )
from apps.news.serializers import (
                                   CategorySerializers, 
                                   LocationSerializers, 
                                   SearchFilterSerializers,
                                   NewsPostSerializers,
                                   FilterNewsSerializers,
                                   DivisionSerializer,
                                   DistrictSerializer,
                                   UpazilaSerializer
                                   )

#Category views


class CategoryListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializers

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


class CategoryCreateViews(views.APIView):
    serializer_class = CategorySerializers
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Category Successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create category"}, status=status.HTTP_400_BAD_REQUEST)
    

class CategoryRetrieveUpdateDestroyApiViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializers
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Category deleted successfully"}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Category updated successfully", "category": response.data}, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Category partially updated successfully", "category": response.data}, status=status.HTTP_200_OK)

#Location views


class LocationListViews(generics.ListAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializers

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)
    

class LocationCreateViews(views.APIView):
    serializer_class = LocationSerializers
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            division = serializer.validated_data['division'] 
            district = serializer.validated_data['district'] 
            upazila = serializer.validated_data['upazila']
            # print(division, district, upazila)
            if not Division.objects.filter(name=division).exists():
                Division.objects.create(name=division)
            if not District.objects.filter(name=district).exists():
                District.objects.create(name=district, division=Division.objects.get(name=division))
            if not Upazila.objects.filter(name=upazila).exists():
                Upazila.objects.create(name=upazila, district=District.objects.get(name=district))

            serializer.save()
            return Response({"message": "Location Successfully Created"}, status=status.HTTP_200_OK)
        return Response({"message": "Failed to create location"}, status=status.HTTP_400_BAD_REQUEST)


class LocationRetrieveUpdateDestroyApiViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializers
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "Location deleted successfully"}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "Location updated successfully", "location": response.data}, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "Location partially updated successfully", "location": response.data}, status=status.HTTP_200_OK)


class LocationFilterView(generics.CreateAPIView):
    queryset = FilterNews.objects.all()
    serializer_class = FilterNewsSerializers

    def post(self, request):
        filter_location = FilterNewsSerializers(data=request.data)
        if filter_location.is_valid():
            filters = filter_location.validated_data

            division = filters['division']
            district = filters['district']
            upazila = filters['upazila']
            divlocation = Division.objects.all()
            dislocation = District.objects.all()
            upazilalocation = Upazila.objects.all()

            if division and not district and not upazila:
                divlocation = divlocation.filter(name=division.name)
                dislocation = dislocation.filter(division__name=division.name)
                upazilalocation = upazilalocation.filter(district__division__name=division.name)

            if division and district and not upazila:
                divlocation = divlocation.filter(name=division.name)
                dislocation = dislocation.filter(division__name=division.name, name=district.name)
                upazilalocation = upazilalocation.filter(district__name=district.name)

            if division and district and upazila:
                divlocation = divlocation.filter(name=division.name)
                dislocation = dislocation.filter(division__name=division.name, name=district.name)
                upazilalocation = upazilalocation.filter(name=upazila.name, district__name=district.name)

            divSerializer = DivisionSerializer(divlocation, many=True)
            disSerializer = DistrictSerializer(dislocation, many=True)
            upazilaSerializer = UpazilaSerializer(upazilalocation, many=True)
            
            return Response({"division": divSerializer.data, "district": disSerializer.data, "upazila": upazilaSerializer.data}, status=status.HTTP_200_OK)
        return Response(filter_location.errors, status=status.HTTP_400_BAD_REQUEST)   


#---------------- NewsPost for Admin -----------------------

class AllNewsPostAdminViews(generics.ListAPIView):
    queryset = NewsPost.objects.all()
    serializer_class = NewsPostSerializers
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    pagination_class = NewsPostPagination
    ordering_fields = ['created_at']
    search_fields = [ 
                    'headline', 'content', 
                    'category__name', 'location__division', 
                    'location__district', 'location__upazila', 
                    'location__custom_location'
                     ] 

#-------------------- NewsPost for User -----------------------


class NewsPostListApiViews(generics.ListAPIView):
    queryset = NewsPost.objects.all()
    serializer_class = NewsPostSerializers
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    ordering_fields = ['created_at']
    search_fields = ['headline', 'content', 
                     'category__name', 'location__division', 
                     'location__district', 'location__upazila', 
                     'location__custom_location'
                     ]
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        return Response(response.data, status=status.HTTP_200_OK)


class NewsPostCreateViews(views.APIView):
    serializer_class = NewsPostSerializers
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            # serializer.validated_data['editor'] = request.user
            # serializer.validated_data['category_name'] = serializer.validated_data['category']
            # print('category print', serializer.validated_data['category'])
            serializer.save()
            return Response({"message": "News Post Successfully Created"}, status=status.HTTP_201_CREATED)
        return Response({"message": "Failed to create News Post"}, status=status.HTTP_400_BAD_REQUEST)


class NewsPostRetrieveUpdateDestroyApiViews(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewsPost.objects.all()
    serializer_class = NewsPostSerializers
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        return Response({"message": "News Post deleted successfully"}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({"message": "News Post updated successfully", "newspost": response.data}, status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({"message": "News Post partially updated successfully", "newspost": response.data}, status=status.HTTP_200_OK)
    

class NewsPostFilterView(views.APIView):

    def post(self, request):
        filter_post = FilterNewsSerializers(data=request.data)
        if filter_post.is_valid():
            filters = filter_post.validated_data
            division = filters['division']
            district = filters['district']
            upazila = filters['upazila']
            query = NewsPost.objects.all()
            
            if division and not district and not upazila:
                # print("sudu division", division.name)
                query = query.filter(location__division=division.name)

            if not division and district and not upazila:
                query = query.filter(location__district=district.name)

            if not division and not district and upazila:
                query = query.filter(location__upazila=upazila.name)

            if division and district and not upazila:
                query = query.filter(location__district=district.name, location__division=division.name)

            if not division and district and upazila:
                query = query.filter(location__upazila=upazila, location__district=district.name)
            
            if division and district and upazila:
                query = query.filter(location__upazila=upazila, location__division=division.name, location__district=district.name)
            
            serializer = NewsPostSerializers(query, many=True)
            
            return Response({"post": serializer.data}, status=status.HTTP_200_OK)
        return Response(filter_post.errors, status=status.HTTP_400_BAD_REQUEST)


class NewsPostSearchFilterView(views.APIView):
    def post(self, request):
        search_filter = SearchFilterSerializers(data=request.data)
        if search_filter.is_valid():
            filters = search_filter.validated_data
            query = NewsPost.objects.all()
           
            if filters.get('division'):
                query = query.filter(location__division=filters['division'])
            if filters.get('district'):
                query = query.filter(location__district=filters['district'])
            if filters.get('upazila'):
                query = query.filter(location__upazila=filters['upazila'])
            if filters.get('category'):
                query = query.filter(category=filters['category'])
            
            serializer = NewsPostSerializers(query, many=True)
            return Response(serializer.data)
        return Response(search_filter.errors, status=status.HTTP_400_BAD_REQUEST)