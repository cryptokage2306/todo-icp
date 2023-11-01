use candid::CandidType;
use ic_cdk::api::caller as caller_api;
use ic_cdk::export::candid;
use ic_cdk_macros::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;

type PrincipalName = Vec<u8>;

#[derive(Clone, CandidType, Serialize, Deserialize)]
pub struct Todo {
    id: u128,
    task: String,
}

thread_local! {
    // Define dapp limits - important for security assurance
    static MAX_USERS: usize = 1_000;
    static MAX_TODO_PER_USER: usize = 500;
    static MAX_TODO_CHARS: usize = 1000;

    pub static NEXT_TODO: RefCell<u128> = RefCell::new(0);
    pub static TODO_BY_USER: RefCell<BTreeMap<PrincipalName, Vec<Todo>>> = RefCell::new(BTreeMap::new());
}

fn caller() -> PrincipalName {
    caller_api().as_slice().to_owned()
}

#[init]
fn init() {}

/// Returns the current number of users.
fn get_user_count() -> usize {
    TODO_BY_USER.with(|todo_ref| todo_ref.borrow().keys().len())
}

fn is_id_valid(id: u128) -> bool {
    MAX_TODO_PER_USER
        .with(|max_todo_per_user| id < (*max_todo_per_user as u128) * (get_user_count() as u128))
}

/// Returns (a future of) this [caller]'s todos.
/// Panics:
///     [caller] is the unknown identity
///     [caller] is not a registered user
#[query]
fn get_todos() -> Vec<Todo> {
    let user = caller();
    TODO_BY_USER.with(|todo_ref| todo_ref.borrow().get(&user).cloned().unwrap_or_default())
}

/// Delete this [caller]'s todo with given id. If none of the
/// existing todos have this id, do nothing.
/// [id]: the id of the todo to be deleted
///
/// Panics:
///      [caller] is the anonymous identity
///      [caller] is not a registered user
///      [id] is get_user_countsonable; see [is_id_valid]
#[update]
fn delete_todo(todo_id: u128) {
    let user = caller();
    assert!(is_id_valid(todo_id));
    // shared ownership borrowing
    TODO_BY_USER.with(|todo_ref| {
        let mut writer = todo_ref.borrow_mut();
        if let Some(v) = writer.get_mut(&user) {
            v.retain(|item| item.id != todo_id);
        }
    });
}

/// Returns (a future of) this [caller]'s todos.
/// get_user_count
///     [caller] is the unknown identity
///     [caller] is not a registered user
///     [todo.task] exceeds [MAX_TODO_CHARS]
///     [todo.id] is unreasonable; see [is_id_valid]
#[update]
fn update_todo(todos: Todo) {
    let user = caller();
    assert!(todos.task.chars().count() <= MAX_TODO_CHARS.with(|mnc| *mnc));
    assert!(is_id_valid(todos.id));

    TODO_BY_USER.with(|todos_ref| {
        let mut writer = todos_ref.borrow_mut();
        if let Some(old_todo) = writer
            .get_mut(&user)
            .and_then(|td| td.iter_mut().find(|t| t.id == todos.id))
        {
            old_todo.task = todos.task;
        }
    })
}

/// Add new todo for this [caller].
///      [todo]: (encrypted) content of this todo
///
/// Returns:
///      Future of unit
/// Panics:
///      [caller] is the anonymous identity
///      [caller] is not a registered user
///      [todo] exceeds [MAX_TODO_CHARS]
///      User already has [MAX_TODOS_PER_USER] todos
///      [todo] would be for a new user and [MAX_USERS] is exceeded
#[update]
fn add_todo(task: String) {
    let user = caller();
    assert!(task.chars().count() <= MAX_TODO_CHARS.with(|mtc| *mtc));
    let todo_id = NEXT_TODO.with(|counter_ref| {
        let mut writer = counter_ref.borrow_mut();
        *writer += 1;
        *writer
    });

    let user_count = get_user_count();
    TODO_BY_USER.with(|todos_ref| {
        let mut writer = todos_ref.borrow_mut();
        let user_todos = writer.entry(user).or_insert_with(|| {
            // caller unknown ==> check invariants
            // A. can we add a new user?
            assert!(MAX_USERS.with(|mu| user_count < *mu));
            vec![]
        });

        assert!(user_todos.len() < MAX_TODO_PER_USER.with(|mtpu| *mtpu));

        user_todos.push(Todo {
            id: todo_id,
            task: task,
        });
    });
}
