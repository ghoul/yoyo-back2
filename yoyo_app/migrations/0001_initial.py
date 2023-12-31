# Generated by Django 4.2.5 on 2023-09-25 11:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('1A', '1A'), ('2A', '3A'), ('3A', '3A'), ('4A', '4A'), ('5A', '5A')], max_length=25)),
            ],
        ),
        migrations.CreateModel(
            name='Trick',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=25)),
                ('description', models.CharField(max_length=200)),
                ('link', models.CharField(max_length=100)),
                ('category', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='yoyo_app.category')),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('text', models.CharField(max_length=200)),
                ('trick', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='comments', to='yoyo_app.trick')),
            ],
        ),
    ]
