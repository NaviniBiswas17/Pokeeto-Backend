<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class ContentSection extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'content_sections';
    protected $fillable = [
        'name',
        'slug',
        'status',
        'order',
    ];


}
