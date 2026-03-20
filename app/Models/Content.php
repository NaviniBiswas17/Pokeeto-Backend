<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class Content extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'contents';
    protected $fillable = [
        'section_id',
        'title',
        'description',
        'type',
        'media_url',
        'thumbnail',
        'is_featured',
        'status',
    ];

    public function section()
    {
        return $this->belongsTo(ContentSection::class, 'section_id');
    }

}
