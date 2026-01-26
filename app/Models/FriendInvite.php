<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class FriendInvite extends Authenticatable
{
    protected $table = 'friend_invites';
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasApiTokens,HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'inviter_user_id',
        'invitee_email',
        'invite_token',
        'processStatus',
        'status',
        'sent_at',
        'accepted_at',
    ];
}
