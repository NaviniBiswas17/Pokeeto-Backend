<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class Transaction extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'transactions';
    protected $fillable = [
        'user_id',
        'account_id',
        'target_account_id',
        'contributor_id',
        'transaction_type',
        'flow',
        'amount',
        'currency',
        'description',
        'processStatus',
        'status',
        'reference'
    ];


}
