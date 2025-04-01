;; Data Collection Contract
;; Securely stores trial results and observations

;; Error codes
(define-constant ERR_UNAUTHORIZED u1)
(define-constant ERR_INVALID_TRIAL u2)
(define-constant ERR_INVALID_PARTICIPANT u3)
(define-constant ERR_INVALID_DATA_POINT u4)
(define-constant ERR_TRIAL_INACTIVE u5)

;; Data structures
(define-map data-points
  {
    data-id: (string-ascii 32)
  }
  {
    trial-id: (string-ascii 32),
    participant-id: (string-ascii 32),
    data-type: (string-ascii 32),
    data-hash: (buff 32),
    timestamp: uint,
    collector: principal,
    metadata: (string-utf8 500)
  }
)

(define-map data-access
  {
    data-id: (string-ascii 32),
    accessor: principal
  }
  {
    access-level: (string-ascii 20),
    granted-by: principal,
    granted-at: uint
  }
)

(define-map authorized-principals
  { principal: principal }
  { role: (string-ascii 20) }
)

;; Read-only functions
(define-read-only (get-data-point (data-id (string-ascii 32)))
  (map-get? data-points { data-id: data-id })
)

(define-read-only (check-data-access (data-id (string-ascii 32)) (accessor principal))
  (map-get? data-access { data-id: data-id, accessor: accessor })
)

(define-read-only (is-authorized (caller principal) (required-role (string-ascii 20)))
  (match (map-get? authorized-principals { principal: caller })
    auth-data (is-eq (get role auth-data) required-role)
    false
  )
)

;; Public functions
(define-public (record-data-point
    (data-id (string-ascii 32))
    (trial-id (string-ascii 32))
    (participant-id (string-ascii 32))
    (data-type (string-ascii 32))
    (data-hash (buff 32))
    (metadata (string-utf8 500))
  )
  (begin
    ;; Only data collectors, investigators, or coordinators can record data
    (asserts! (or
                (is-authorized tx-sender "data-collector")
                (is-authorized tx-sender "investigator")
                (is-authorized tx-sender "coordinator")
              )
              (err ERR_UNAUTHORIZED))

    ;; Record the data point
    (map-set data-points
      { data-id: data-id }
      {
        trial-id: trial-id,
        participant-id: participant-id,
        data-type: data-type,
        data-hash: data-hash,
        timestamp: (default-to u0 (get-block-info? time (- block-height u1))),
        collector: tx-sender,
        metadata: metadata
      }
    )

    ;; Grant access to the collector
    (map-set data-access
      { data-id: data-id, accessor: tx-sender }
      {
        access-level: "full",
        granted-by: tx-sender,
        granted-at: (default-to u0 (get-block-info? time (- block-height u1)))
      }
    )

    (ok true)
  )
)

(define-public (update-data-point
    (data-id (string-ascii 32))
    (new-data-hash (buff 32))
    (new-metadata (string-utf8 500))
  )
  (let (
    (data-point (unwrap! (get-data-point data-id) (err ERR_INVALID_DATA_POINT)))
  )
    ;; Only the original collector or an administrator can update data
    (asserts! (or
                (is-eq tx-sender (get collector data-point))
                (is-authorized tx-sender "admin")
              )
              (err ERR_UNAUTHORIZED))

    ;; Update the data point
    (map-set data-points
      { data-id: data-id }
      (merge data-point {
        data-hash: new-data-hash,
        metadata: new-metadata
      })
    )

    (ok true)
  )
)

(define-public (grant-data-access
    (data-id (string-ascii 32))
    (accessor principal)
    (access-level (string-ascii 20))
  )
  (let (
    (data-point (unwrap! (get-data-point data-id) (err ERR_INVALID_DATA_POINT)))
  )
    ;; Only the original collector, an administrator, or a data manager can grant access
    (asserts! (or
                (is-eq tx-sender (get collector data-point))
                (is-authorized tx-sender "admin")
                (is-authorized tx-sender "data-manager")
              )
              (err ERR_UNAUTHORIZED))

    ;; Grant access
    (map-set data-access
      { data-id: data-id, accessor: accessor }
      {
        access-level: access-level,
        granted-by: tx-sender,
        granted-at: (default-to u0 (get-block-info? time (- block-height u1)))
      }
    )

    (ok true)
  )
)

(define-public (revoke-data-access
    (data-id (string-ascii 32))
    (accessor principal)
  )
  (let (
    (data-point (unwrap! (get-data-point data-id) (err ERR_INVALID_DATA_POINT)))
    (access (unwrap! (check-data-access data-id accessor) (err ERR_UNAUTHORIZED)))
  )
    ;; Only the original granter, an administrator, or a data manager can revoke access
    (asserts! (or
                (is-eq tx-sender (get granted-by access))
                (is-authorized tx-sender "admin")
                (is-authorized tx-sender "data-manager")
              )
              (err ERR_UNAUTHORIZED))

    ;; Revoke access by deleting the entry
    (map-delete data-access { data-id: data-id, accessor: accessor })

    (ok true)
  )
)

(define-public (bulk-record-data
    (data-ids (list 10 (string-ascii 32)))
    (trial-id (string-ascii 32))
    (participant-id (string-ascii 32))
    (data-type (string-ascii 32))
    (data-hashes (list 10 (buff 32)))
    (metadata-list (list 10 (string-utf8 500)))
  )
  (begin
    ;; Only data collectors, investigators, or coordinators can record data
    (asserts! (or
                (is-authorized tx-sender "data-collector")
                (is-authorized tx-sender "investigator")
                (is-authorized tx-sender "coordinator")
              )
              (err ERR_UNAUTHORIZED))

    ;; Use fold to process each data point
    (ok (fold record-data-point-internal data-ids {
      trial-id: trial-id,
      participant-id: participant-id,
      data-type: data-type,
      data-hashes: data-hashes,
      metadata-list: metadata-list,
      index: u0,
      success: true
    }))
  )
)

;; Internal helper function for bulk recording
(define-private (record-data-point-internal
    (data-id (string-ascii 32))
    (state {
      trial-id: (string-ascii 32),
      participant-id: (string-ascii 32),
      data-type: (string-ascii 32),
      data-hashes: (list 10 (buff 32)),
      metadata-list: (list 10 (string-utf8 500)),
      index: uint,
      success: bool
    })
  )
  (begin
    ;; Only proceed if previous operations were successful
    (if (get success state)
      (let (
        (data-hash (unwrap! (element-at (get data-hashes state) (get index state)) state))
        (metadata (unwrap! (element-at (get metadata-list state) (get index state)) state))
      )
        ;; Record the data point
        (map-set data-points
          { data-id: data-id }
          {
            trial-id: (get trial-id state),
            participant-id: (get participant-id state),
            data-type: (get data-type state),
            data-hash: data-hash,
            timestamp: (default-to u0 (get-block-info? time (- block-height u1))),
            collector: tx-sender,
            metadata: metadata
          }
        )

        ;; Grant access to the collector
        (map-set data-access
          { data-id: data-id, accessor: tx-sender }
          {
            access-level: "full",
            granted-by: tx-sender,
            granted-at: (default-to u0 (get-block-info? time (- block-height u1)))
          }
        )

        ;; Return updated state
        (merge state { index: (+ (get index state) u1) })
      )
      ;; If previous operations failed, just return the state unchanged
      state
    )
  )
)

;; Administrative functions
(define-public (authorize-principal
    (user principal)
    (role (string-ascii 20))
  )
  (begin
    ;; Only administrators can authorize principals
    (asserts! (is-authorized tx-sender "admin") (err ERR_UNAUTHORIZED))

    ;; Set the authorization
    (map-set authorized-principals
      { principal: user }
      { role: role }
    )
    (ok true)
  )
)

