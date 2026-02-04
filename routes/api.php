<?php

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


Route::post('login', [Controller::class, 'login']);
Route::post('dashboard', [Controller::class, 'dashboard']);
Route::post('loginGuest', [Controller::class, 'loginGuest']);
Route::post('sendOtp', [Controller::class, 'sendOtp']);
// Route::post('verifyOtp', [Controller::class, 'verifyOtp']);
// Route::post('confirmPass', [Controller::class, 'confirmPass']);


Route::post('addAccount', [Controller::class, 'addAccount']);
Route::post('getAccountList', [Controller::class, 'getAccountList']);
Route::post('getAccount', [Controller::class, 'getAccount']);

Route::post('addContributor', [Controller::class, 'addContributor']);
Route::post('removeContributor', [Controller::class, 'removeContributor']);
Route::post('getContributorList', [Controller::class, 'getContributorList']);

Route::post('getUserCategoryList', [Controller::class, 'getUserCategoryList']);
Route::post('addUserCategory', [Controller::class, 'addUserCategory']);

Route::post('getUserDetails', [Controller::class, 'getUserDetails']);
Route::post('updateUserSetting', [Controller::class, 'updateUserSetting']);

Route::post('inviteFriend', [Controller::class, 'inviteFriend']);
Route::post('editInviteFriend', [Controller::class, 'editInviteFriend']);
Route::post('resendInviteFriend', [Controller::class, 'resendInviteFriend']);
Route::post('inviteFriendList', [Controller::class, 'inviteFriendList']);

Route::post('getTransactionList', [Controller::class, 'getTransactionList']);
Route::post('getTransactionListCustom', [Controller::class, 'getTransactionListCustom']);
Route::post('addTransaction', [Controller::class, 'addTransaction']);
Route::post('getTransaction', [Controller::class, 'getTransaction']);
Route::post('deleteTransaction', [Controller::class, 'deleteTransaction']);
Route::post('editTransaction', [Controller::class, 'editTransaction']);

Route::post('getTransferList', [Controller::class, 'getTransferList']);
Route::post('getTransferListCustom', [Controller::class, 'getTransferListCustom']);
Route::post('getReminderList', [Controller::class, 'getReminderList']);
Route::post('getReminderListCustom', [Controller::class, 'getReminderListCustom']);



Route::post('addKid', [Controller::class, 'addKid']);
Route::post('editKid', [Controller::class, 'editKid']);
Route::post('getKidDetails', [Controller::class, 'getKidDetails']);
Route::post('getKidDetailList', [Controller::class, 'getKidDetailList']);

Route::post('addKidTask', [Controller::class, 'addKidTask']);
Route::post('editKidTask', [Controller::class, 'editKidTask']);
Route::post('deleteKidTask', [Controller::class, 'deleteKidTask']);
Route::post('getKidTask', [Controller::class, 'getKidTask']);
Route::post('getKidTaskDetails', [Controller::class, 'getKidTaskDetails']);

Route::post('addKidGoal', [Controller::class, 'addKidGoal']);
Route::post('editKidGoal', [Controller::class, 'editKidGoal']);
Route::post('deleteKidGoal', [Controller::class, 'deleteKidGoal']);
Route::post('getKidGoal', [Controller::class, 'getKidGoal']);
Route::post('getKidGoalDetails', [Controller::class, 'getKidGoalDetails']);



Route::post('getKidTransactionList', [Controller::class, 'getKidTransactionList']);
Route::post('addKidTransaction', [Controller::class, 'addKidTransaction']);
Route::post('getKidTransactionDetail', [Controller::class, 'getKidTransactionDetail']);
Route::post('deleteKidTransaction', [Controller::class, 'deleteKidTransaction']);
Route::post('editKidTransaction', [Controller::class, 'editKidTransaction']);
