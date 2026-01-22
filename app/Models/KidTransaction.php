<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class KidTransaction extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'kid_transactions';
    protected $fillable = [
        'parent_id',
        'kid_id',
        'parent_account_id',
        'transaction_type',
        'transactionDate',
        'flow',
        'amount',
        'currency',
        'description',
        'processStatus',
        'status',
        'reference'
    ];


}
