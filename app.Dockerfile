FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source

COPY ./Cut-Roll-Identity/src/Cut-Roll-Identity.Api/*.csproj .Cut-Roll-Identity/src/Cut-Roll-Identity.Api/
COPY ./Cut-Roll-Identity/src/Cut-Roll-Identity.Infrastructure/*.csproj .Cut-Roll-Identity/src/Cut-Roll-Identity.Infrastructure/
COPY ./Cut-Roll-Identity/src/Cut-Roll-Identity.Core/*.csproj .Cut-Roll-Identity/src/Cut-Roll-Identity.Core/

COPY . .

RUN dotnet publish Cut-Roll-Identity/src/Cut-Roll-Identity.Api/Cut-Roll-Identity.Api.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT [ "dotnet", "Cut-Roll-Identity.Api.dll" ]